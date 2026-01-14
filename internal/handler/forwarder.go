package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"

	"quic-relay/internal/debug"
)

func init() {
	Register("forwarder", NewForwarderHandler)
}

// ForwarderHandler handles UDP packet forwarding between clients and backends.
type ForwarderHandler struct {
	sessionCounter atomic.Uint64
}

// NewForwarderHandler creates a new forwarder handler.
func NewForwarderHandler(_ json.RawMessage) (Handler, error) {
	return &ForwarderHandler{}, nil
}

// Name returns the handler name.
func (h *ForwarderHandler) Name() string {
	return "forwarder"
}

// OnConnect establishes a UDP session to the backend.
func (h *ForwarderHandler) OnConnect(ctx *Context) Result {
	// Get backend from context (set by router handler)
	backend := ctx.GetString("backend")
	if backend == "" {
		return Result{Action: Drop, Error: errors.New("no backend address")}
	}

	// Resolve backend address
	backendAddr, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		return Result{Action: Drop, Error: err}
	}

	// Create UDP connection to backend
	backendConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		return Result{Action: Drop, Error: err}
	}

	// Create session
	now := time.Now()
	session := &Session{
		ID:          h.sessionCounter.Add(1),
		BackendAddr: backendAddr,
		BackendConn: backendConn,
		CreatedAt:   now,
	}
	session.SetClientAddr(ctx.ClientAddr)
	session.LastActivity.Store(now.Unix())
	ctx.Session = session

	log.Printf("[forwarder] session=%d %s -> %s", session.ID, ctx.ClientAddr, backend)

	// Forward the initial packet to backend
	if len(ctx.InitialPacket) > 0 {
		_, err := backendConn.Write(ctx.InitialPacket)
		if err != nil {
			log.Printf("[forwarder] failed to forward initial packet: %v", err)
			backendConn.Close()
			return Result{Action: Drop, Error: err}
		}
	}

	// Clear InitialPacket to free memory (~1.4KB per session)
	ctx.InitialPacket = nil

	// Start goroutine to read from backend and send to client
	go h.backendToClient(ctx, session)

	return Result{Action: Handled}
}

// OnPacket forwards packets from client to backend.
func (h *ForwarderHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	if ctx.Session == nil {
		return Result{Action: Drop, Error: errors.New("no session")}
	}

	// Check if session is being closed (prevents use-after-close race)
	if ctx.Session.IsClosed() {
		return Result{Action: Drop}
	}

	// Update activity timestamp
	ctx.Session.Touch()

	if dir == Inbound {
		// Client -> Backend
		debug.Printf(" client->backend: %d bytes, first byte: 0x%02x", len(packet), packet[0])
		_, err := ctx.Session.BackendConn.Write(packet)
		if err != nil {
			log.Printf("[forwarder] write to backend failed: %v", err)
			return Result{Action: Drop, Error: err}
		}
	}
	// Outbound is handled by backendToClient goroutine

	return Result{Action: Handled}
}

// OnDisconnect cleans up the session.
func (h *ForwarderHandler) OnDisconnect(ctx *Context) {
	if ctx.Session != nil {
		// Atomically mark session as closed (prevents concurrent writes)
		if !ctx.Session.Close() {
			return // Already closed by another goroutine
		}
		log.Printf("[forwarder] closing session=%d duration=%v",
			ctx.Session.ID, time.Since(ctx.Session.CreatedAt))
		ctx.Session.BackendConn.Close()
	}
}

// backendToClient reads packets from backend and sends to client.
// Uses buffer pool to avoid per-session 64KB allocations.
func (h *ForwarderHandler) backendToClient(ctx *Context, session *Session) {
	for {
		// Check if session is closed before reading
		if session.IsClosed() {
			return
		}

		// Get buffer from pool for this read
		buf := GetBuffer()

		// Set read deadline to detect idle connections
		session.BackendConn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		n, err := session.BackendConn.Read(*buf)
		if err != nil {
			// Connection closed or timed out
			PutBuffer(buf)
			return
		}

		// Check again after read (session may have closed during blocking read)
		if session.IsClosed() {
			PutBuffer(buf)
			return
		}

		// Update activity timestamp (bidirectional tracking)
		session.Touch()

		// Notify proxy of server packets to learn server's SCID(s)
		// This enables routing subsequent client packets that use server's CID as DCID
		ctx.NotifyServerPacket((*buf)[:n])

		debug.Printf(" backend->client: %d bytes, first byte: 0x%02x", n, (*buf)[0])

		// Send to client via proxy's UDP connection
		if ctx.ProxyConn != nil {
			_, err = ctx.ProxyConn.WriteToUDP((*buf)[:n], session.ClientAddr())
			if err != nil {
				log.Printf("[forwarder] write to client failed: %v", err)
				PutBuffer(buf)
				return
			}
			debug.Printf(" sent to client %s", session.ClientAddr())
		}

		// Return buffer to pool after use
		PutBuffer(buf)
	}
}
