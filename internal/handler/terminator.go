package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"quic-relay/internal/debug"
)

func init() {
	Register("terminator", NewTerminatorHandler)
}

// TerminatorConfig holds configuration for the terminator handler.
type TerminatorConfig struct {
	Listen string `json:"listen"` // ":5521" or "auto" for ephemeral port
	Cert   string `json:"cert"`   // Path to TLS certificate
	Key    string `json:"key"`    // Path to TLS private key
}

// backendEntry tracks a backend address with reference counting.
// Multiple connections with the same SNI share the same entry.
type backendEntry struct {
	addr     string
	refCount atomic.Int32
}

// TerminatorHandler terminates QUIC connections and bridges them to backends.
// It runs an internal quic.Listener and uses the transparent proxy as a frontend.
type TerminatorHandler struct {
	config       TerminatorConfig
	listener     *quic.Listener
	internalAddr string

	// SNI → *backendEntry mapping (set by OnConnect, read by internal listener)
	backends sync.Map

	// Session tracking
	sessionCount atomic.Int64
	sessions     sync.Map // sessionID → *terminatorSession

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTerminatorHandler creates a new terminator handler.
func NewTerminatorHandler(raw json.RawMessage) (Handler, error) {
	var cfg TerminatorConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	h := &TerminatorHandler{config: cfg}
	h.ctx, h.cancel = context.WithCancel(context.Background())

	// Load certificate
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-echo", "h3", "hq-interop"}, // Accept common protocols
	}

	// Start internal listener
	addr := cfg.Listen
	if addr == "auto" || addr == "" {
		addr = "localhost:0" // Ephemeral port
	}

	listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	h.listener = listener
	h.internalAddr = listener.Addr().String()

	log.Printf("[terminator] internal listener on %s", h.internalAddr)

	// Start accept loop in goroutine
	h.wg.Add(1)
	go h.acceptLoop()

	return h, nil
}

// Name returns the handler name.
func (h *TerminatorHandler) Name() string {
	return "terminator"
}

// OnConnect stores backend mapping and redirects to internal listener.
func (h *TerminatorHandler) OnConnect(ctx *Context) Result {
	sni := ctx.Hello.SNI
	backend := ctx.GetString("backend")

	if sni == "" || backend == "" {
		return Result{Action: Drop, Error: errors.New("missing SNI or backend")}
	}

	// Store or increment ref count for this SNI → backend mapping
	entry, loaded := h.backends.LoadOrStore(sni, &backendEntry{addr: backend})
	be := entry.(*backendEntry)
	if loaded {
		// Entry existed, just increment ref count
		be.refCount.Add(1)
	} else {
		// New entry, set initial ref count
		be.refCount.Store(1)
	}

	// Redirect to internal listener
	ctx.Set("backend", h.internalAddr)

	log.Printf("[terminator] %s → %s (via %s)", sni, backend, h.internalAddr)

	return Result{Action: Continue}
}

// OnPacket does nothing - ForwarderHandler handles packet forwarding.
func (h *TerminatorHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect decrements backend reference count.
func (h *TerminatorHandler) OnDisconnect(ctx *Context) {
	if ctx.Hello == nil {
		return
	}

	sni := ctx.Hello.SNI
	if entry, ok := h.backends.Load(sni); ok {
		be := entry.(*backendEntry)
		if be.refCount.Add(-1) <= 0 {
			h.backends.Delete(sni)
		}
	}
}

// acceptLoop accepts connections on the internal listener.
func (h *TerminatorHandler) acceptLoop() {
	defer h.wg.Done()

	log.Printf("[terminator] accept loop started, waiting for connections...")

	for {
		debug.Printf(" terminator: calling Accept()...")
		conn, err := h.listener.Accept(h.ctx)
		if err != nil {
			// Context cancelled or listener closed
			log.Printf("[terminator] accept error: %v", err)
			return
		}

		log.Printf("[terminator] accepted connection from %s, TLS: %+v", conn.RemoteAddr(), conn.ConnectionState().TLS.ServerName)
		h.wg.Add(1)
		go h.handleConnection(conn)
	}
}

// handleConnection handles a single client connection.
func (h *TerminatorHandler) handleConnection(clientConn *quic.Conn) {
	defer h.wg.Done()

	// Get SNI and ALPN from TLS state
	tlsState := clientConn.ConnectionState().TLS
	sni := tlsState.ServerName
	alpn := tlsState.NegotiatedProtocol

	// Lookup backend
	entry, ok := h.backends.Load(sni)
	if !ok {
		log.Printf("[terminator] no backend for SNI %q", sni)
		clientConn.CloseWithError(0x01, "no backend")
		return
	}
	backend := entry.(*backendEntry).addr

	// Dial backend with timeout, using same ALPN as client
	dialCtx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()

	backendTLS := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni, // Pass through SNI
	}
	if alpn != "" {
		backendTLS.NextProtos = []string{alpn}
	}

	serverConn, err := quic.DialAddr(dialCtx, backend, backendTLS, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Printf("[terminator] dial backend %s failed: %v", backend, err)
		clientConn.CloseWithError(0x02, "backend unreachable")
		return
	}

	// Check if client is still connected
	select {
	case <-clientConn.Context().Done():
		serverConn.CloseWithError(0, "client gone")
		return
	default:
	}

	// Create session and start bridging
	session := newTerminatorSession(clientConn, serverConn)
	sessionID := h.sessionCount.Add(1)
	h.sessions.Store(sessionID, session)
	defer h.sessions.Delete(sessionID)

	log.Printf("[terminator] session %d: %s ↔ %s (ALPN=%s)", sessionID, sni, backend, alpn)

	// Bridge streams (blocks until session ends)
	session.bridge(h.ctx)

	log.Printf("[terminator] session %d closed", sessionID)
}

// Shutdown gracefully shuts down the terminator.
func (h *TerminatorHandler) Shutdown(ctx context.Context) error {
	// Cancel context (stops accept loop)
	h.cancel()

	// Close listener (stops new connections)
	h.listener.Close()

	// Close all sessions
	h.sessions.Range(func(key, val any) bool {
		val.(*terminatorSession).Close()
		return true
	})

	// Wait for all goroutines
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// terminatorSession represents a bridged connection between client and server.
type terminatorSession struct {
	clientConn *quic.Conn
	serverConn *quic.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	closed     atomic.Bool
	wg         sync.WaitGroup
}

func newTerminatorSession(client, server *quic.Conn) *terminatorSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &terminatorSession{
		clientConn: client,
		serverConn: server,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (s *terminatorSession) bridge(parentCtx context.Context) {
	// Monitor for connection close from either side
	go func() {
		select {
		case <-s.clientConn.Context().Done():
		case <-s.serverConn.Context().Done():
		case <-parentCtx.Done():
		}
		s.Close()
	}()

	// 4 goroutines for all stream types:
	// 1. Client → Server (bidirectional)
	// 2. Server → Client (bidirectional)
	// 3. Client → Server (unidirectional)
	// 4. Server → Client (unidirectional)

	s.wg.Add(4)
	go s.bridgeBidirectional(s.clientConn, s.serverConn)  // Client-initiated
	go s.bridgeBidirectional(s.serverConn, s.clientConn)  // Server-initiated
	go s.bridgeUnidirectional(s.clientConn, s.serverConn) // Client → Server
	go s.bridgeUnidirectional(s.serverConn, s.clientConn) // Server → Client

	s.wg.Wait()
}

func (s *terminatorSession) bridgeBidirectional(src, dst *quic.Conn) {
	defer s.wg.Done()

	debug.Printf(" bridgeBidirectional: waiting for streams from %s", src.RemoteAddr())

	for {
		srcStream, err := src.AcceptStream(s.ctx)
		if err != nil {
			debug.Printf(" bridgeBidirectional: AcceptStream error: %v", err)
			return // Connection closed
		}

		debug.Printf(" bridgeBidirectional: accepted stream %d from %s", srcStream.StreamID(), src.RemoteAddr())

		dstStream, err := dst.OpenStream()
		if err != nil {
			debug.Printf(" bridgeBidirectional: OpenStream error: %v", err)
			srcStream.Close()
			return
		}

		debug.Printf(" bridgeBidirectional: opened stream %d to %s", dstStream.StreamID(), dst.RemoteAddr())

		s.wg.Add(1)
		go s.copyBidirectionalStream(srcStream, dstStream)
	}
}

func (s *terminatorSession) bridgeUnidirectional(src, dst *quic.Conn) {
	defer s.wg.Done()

	for {
		srcStream, err := src.AcceptUniStream(s.ctx)
		if err != nil {
			return // Connection closed
		}

		dstStream, err := dst.OpenUniStream()
		if err != nil {
			srcStream.CancelRead(0)
			return
		}

		s.wg.Add(1)
		go s.copyUnidirectionalStream(srcStream, dstStream)
	}
}

func (s *terminatorSession) copyBidirectionalStream(src, dst *quic.Stream) {
	defer s.wg.Done()
	defer src.Close()
	defer dst.Close()

	debug.Printf(" copyBidirectionalStream: bridging stream %d <-> %d", src.StreamID(), dst.StreamID())

	done := make(chan struct{}, 2)

	// src → dst
	go func() {
		n, err := io.Copy(dst, src)
		debug.Printf(" stream %d -> %d: copied %d bytes, err=%v", src.StreamID(), dst.StreamID(), n, err)
		dst.Close() // Signal write-end closed (sends FIN)
		done <- struct{}{}
	}()

	// dst → src
	go func() {
		n, err := io.Copy(src, dst)
		debug.Printf(" stream %d -> %d: copied %d bytes, err=%v", dst.StreamID(), src.StreamID(), n, err)
		src.Close()
		done <- struct{}{}
	}()

	// Wait for both or session close
	select {
	case <-done:
		<-done
	case <-s.ctx.Done():
		debug.Printf(" copyBidirectionalStream: context cancelled")
	}
}

func (s *terminatorSession) copyUnidirectionalStream(src *quic.ReceiveStream, dst *quic.SendStream) {
	defer s.wg.Done()
	defer dst.Close()

	io.Copy(dst, src)
}

// Close closes the session and both connections.
func (s *terminatorSession) Close() {
	if !s.closed.Swap(true) {
		s.cancel()
		s.clientConn.CloseWithError(0, "session closed")
		s.serverConn.CloseWithError(0, "session closed")
	}
}
