package handler

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// coarseTime holds a Unix timestamp updated once per second.
// Used by Touch() to avoid syscalls on every packet.
var coarseTime atomic.Int64

// StartCoarseClock starts a background goroutine that updates coarseTime every second.
// Call this once at startup before processing packets.
// The goroutine stops when ctx is cancelled.
func StartCoarseClock(ctx context.Context) {
	coarseTime.Store(time.Now().Unix()) // Initialize immediately
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				coarseTime.Store(time.Now().Unix())
			}
		}
	}()
}

// ClientHello contains parsed TLS ClientHello data from QUIC Initial packet.
type ClientHello struct {
	// Raw is a zero-copy slice of the original ClientHello bytes.
	Raw []byte
	// SNI is the Server Name Indication.
	SNI string
	// ALPNProtocols contains the Application Layer Protocol Negotiation values.
	ALPNProtocols []string
}

// Session represents a UDP session between client and backend.
type Session struct {
	ID           uint64
	DCID         []byte                      // Destination Connection ID from Initial packet (session key)
	clientAddr   atomic.Pointer[net.UDPAddr] // Current client address (atomic for connection migration)
	BackendAddr  *net.UDPAddr
	BackendConn  *net.UDPConn
	CreatedAt    time.Time
	LastActivity atomic.Int64 // Unix timestamp - updated atomically on every packet
	closed       atomic.Bool  // Set when session is being closed - prevents use-after-close
}

// Touch updates the last activity timestamp atomically.
// Uses coarse clock (1-second resolution) to avoid syscalls on every packet.
// Safe to call from multiple goroutines.
func (s *Session) Touch() {
	s.LastActivity.Store(coarseTime.Load())
}

// IdleDuration returns time since last activity.
func (s *Session) IdleDuration() time.Duration {
	return time.Since(time.Unix(s.LastActivity.Load(), 0))
}

// Close atomically marks the session as closed.
// Returns true if this call closed the session, false if already closed.
func (s *Session) Close() bool {
	return s.closed.CompareAndSwap(false, true)
}

// IsClosed returns whether the session has been closed.
func (s *Session) IsClosed() bool {
	return s.closed.Load()
}

// DCIDKey returns the DCID as a string key for map lookups.
func (s *Session) DCIDKey() string {
	return string(s.DCID)
}

// ClientAddr returns the current client address (atomic read).
// Safe to call from multiple goroutines.
func (s *Session) ClientAddr() *net.UDPAddr {
	return s.clientAddr.Load()
}

// SetClientAddr updates the client address (atomic write).
// Used for connection migration when client changes IP/port.
func (s *Session) SetClientAddr(addr *net.UDPAddr) {
	s.clientAddr.Store(addr)
}

// Context carries request-scoped data through the handler chain.
// All value access methods are thread-safe.
type Context struct {
	// ClientAddr is the client's UDP address.
	ClientAddr *net.UDPAddr

	// InitialPacket is the first packet received (contains QUIC Initial with ClientHello).
	InitialPacket []byte

	// Hello is the parsed ClientHello (nil until parsed).
	Hello *ClientHello

	// Session is the UDP session state (created by forwarder handler).
	Session *Session

	// ProxyConn is a reference to the proxy's UDP connection for sending responses.
	ProxyConn *net.UDPConn

	// OnServerPacket is called for every Long Header packet from backend.
	// Used by proxy to learn server's SCID(s) for DCID-based routing.
	// Set by proxy before passing context to handlers.
	OnServerPacket func(packet []byte)

	// DropSession immediately removes the session from the proxy.
	// Set by proxy after session is stored. Safe to call multiple times (idempotent).
	// Handlers can call this to immediately terminate a connection.
	DropSession       func()
	dropSessionCalled atomic.Bool

	// values is a thread-safe key-value store for passing data between handlers.
	values map[string]any
	mu     sync.RWMutex
}

// NotifyServerPacket calls OnServerPacket callback for Long Header packets.
// Used to learn new SCIDs from the server during handshake.
func (c *Context) NotifyServerPacket(packet []byte) {
	if c.OnServerPacket != nil && len(packet) > 0 && (packet[0]&0x80) != 0 {
		// Only call for Long Header packets (first bit = 1)
		c.OnServerPacket(packet)
	}
}

// Drop immediately removes the session from the proxy.
// Safe to call multiple times (idempotent) and from any goroutine.
// Does nothing if DropSession callback is not set.
func (c *Context) Drop() {
	if c.DropSession != nil && !c.dropSessionCalled.Swap(true) {
		c.DropSession()
	}
}

// Set stores a value in the context (thread-safe).
func (c *Context) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		c.values = make(map[string]any)
	}
	c.values[key] = value
}

// Get retrieves a value from the context (thread-safe).
func (c *Context) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.values == nil {
		return nil, false
	}
	v, ok := c.values[key]
	return v, ok
}

// GetValue retrieves a typed value from the context (thread-safe).
// Returns zero value and false if key doesn't exist or type doesn't match.
func GetValue[T any](ctx *Context, key string) (T, bool) {
	var zero T
	v, ok := ctx.Get(key)
	if !ok {
		return zero, false
	}
	typed, ok := v.(T)
	if !ok {
		return zero, false
	}
	return typed, ok
}

// GetString retrieves a string value from the context.
func (c *Context) GetString(key string) string {
	if v, ok := c.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetInt retrieves an int value from the context.
func (c *Context) GetInt(key string) int {
	if v, ok := c.Get(key); ok {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

// GetBool retrieves a bool value from the context.
func (c *Context) GetBool(key string) bool {
	if v, ok := c.Get(key); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// GetInt64 retrieves an int64 value from the context.
func (c *Context) GetInt64(key string) int64 {
	if v, ok := c.Get(key); ok {
		if i, ok := v.(int64); ok {
			return i
		}
	}
	return 0
}
