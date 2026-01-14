package proxy

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"quic-relay/internal/debug"
	"quic-relay/internal/handler"
)

// Config represents the proxy configuration.
type Config struct {
	Listen         string                  `json:"listen"`
	Handlers       []handler.HandlerConfig `json:"handlers"`
	SessionTimeout int                     `json:"session_timeout,omitempty"` // Idle timeout in seconds (default: 600)
}

// LoadConfig loads configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfig parses configuration from JSON bytes.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// CryptoAssembler collects CRYPTO frames from multiple Initial packets.
// Production-ready: bounded memory, timeout-based cleanup, cached crypto objects.
type CryptoAssembler struct {
	buffer    []byte    // Pre-allocated buffer, written to at frame offsets
	written   []uint64  // Bitset: track which bytes have been written (128 uint64s = 1KB instead of 8KB)
	maxOffset int       // Highest offset seen
	complete  bool      // ClientHello successfully parsed
	createdAt time.Time // For timeout-based cleanup
	mu        sync.Mutex

	// Cached crypto objects (derived once from DCID, reused for all packets)
	dcid     []byte       // Destination Connection ID used to derive keys
	hpCipher cipher.Block // Header protection cipher
	aead     cipher.AEAD  // AEAD for payload decryption
	clientIV []byte       // Client Initial IV
}

const (
	maxCryptoBufferSize = 8192                     // Max 8KB for ClientHello (more than enough)
	writtenBitsetSize   = maxCryptoBufferSize / 64 // 128 uint64s for bitset
	assemblerTimeout    = 5 * time.Second          // Clean up incomplete assemblers after 5s

	// Bounds for maps to prevent unbounded memory growth
	maxSessions       = 100000
	maxAssemblers     = 50000
	maxPendingPerDCID = 10 // Max buffered packets per DCID
	cleanupInterval   = 30 * time.Second
)

// pendingPacket holds a packet that arrived before its session was created.
type pendingPacket struct {
	data []byte
}

// pendingBuffer holds packets waiting for session creation.
type pendingBuffer struct {
	packets   []pendingPacket
	createdAt time.Time
	mu        sync.Mutex
}

// NewCryptoAssembler creates a new assembler with pre-allocated buffer
func NewCryptoAssembler() *CryptoAssembler {
	return &CryptoAssembler{
		buffer:    make([]byte, maxCryptoBufferSize),
		written:   make([]uint64, writtenBitsetSize),
		createdAt: time.Now(),
	}
}

// setBit marks byte at index as written
func (a *CryptoAssembler) setBit(index int) {
	a.written[index/64] |= 1 << (index % 64)
}

// isSet checks if byte at index was written
func (a *CryptoAssembler) isSet(index int) bool {
	return a.written[index/64]&(1<<(index%64)) != 0
}

// AddFrame adds a single CRYPTO frame's data at its offset
// Returns false if the frame doesn't fit
func (a *CryptoAssembler) AddFrame(offset uint64, data []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Bounds check
	if offset >= maxCryptoBufferSize {
		return false
	}
	end := int(offset) + len(data)
	if end > maxCryptoBufferSize {
		end = maxCryptoBufferSize
		data = data[:maxCryptoBufferSize-int(offset)]
	}

	// Copy data to buffer
	copy(a.buffer[offset:end], data)

	// Mark bytes as written (using bitset)
	for i := int(offset); i < end; i++ {
		a.setBit(i)
	}

	if end > a.maxOffset {
		a.maxOffset = end
	}

	return true
}

// TryParse attempts to parse ClientHello from collected data
// Returns nil if not enough data yet
func (a *CryptoAssembler) TryParse() *handler.ClientHello {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.maxOffset < 6 {
		return nil
	}

	// Check if we have the start of ClientHello
	if a.buffer[0] != 0x01 {
		return nil // Not a ClientHello
	}

	// Get ClientHello length
	hsLen := int(a.buffer[1])<<16 | int(a.buffer[2])<<8 | int(a.buffer[3])
	needed := 4 + hsLen
	if needed > maxCryptoBufferSize {
		needed = maxCryptoBufferSize
	}

	if a.maxOffset < needed {
		return nil // Not enough data yet
	}

	// Check for gaps in the first 'needed' bytes (using bitset)
	for i := 0; i < needed; i++ {
		if !a.isSet(i) {
			return nil // Gap in data
		}
	}

	// We have enough contiguous data, parse it
	hello, err := parseTLSClientHello(a.buffer[:needed])
	if err != nil {
		return nil
	}

	a.complete = true
	return hello
}

// IsExpired checks if the assembler has timed out
func (a *CryptoAssembler) IsExpired() bool {
	return time.Since(a.createdAt) > assemblerTimeout
}

// IsComplete returns whether the ClientHello has been successfully parsed (thread-safe).
func (a *CryptoAssembler) IsComplete() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.complete
}

// InitCrypto derives and caches crypto objects for this DCID.
// Returns error if key derivation fails. Safe to call multiple times.
func (a *CryptoAssembler) InitCrypto(dcid []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Already initialized for this DCID
	if bytes.Equal(a.dcid, dcid) {
		return nil
	}

	key, iv, hp, err := deriveInitialKeys(dcid)
	if err != nil {
		return err
	}

	a.dcid = make([]byte, len(dcid))
	copy(a.dcid, dcid)
	a.clientIV = iv

	a.hpCipher, err = aes.NewCipher(hp)
	if err != nil {
		return err
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	a.aead, err = cipher.NewGCM(aesCipher)
	return err
}

// HasCrypto returns true if crypto objects are initialized.
func (a *CryptoAssembler) HasCrypto() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.aead != nil
}

// GetCrypto returns cached crypto objects for decryption.
// Must call InitCrypto first.
func (a *CryptoAssembler) GetCrypto() (cipher.Block, cipher.AEAD, []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hpCipher, a.aead, a.clientIV
}

// Proxy is the main UDP proxy server.
type Proxy struct {
	listenAddr     string
	conn           *net.UDPConn
	chain          atomic.Pointer[handler.Chain] // Atomic for hot reload
	sessionTimeout atomic.Int64                  // Idle timeout in seconds (atomic for hot reload)
	sessions       sync.Map                      // DCID (string) -> *handler.Context
	sessionCount   atomic.Int64                  // O(1) session counter
	assemblers     sync.Map                      // DCID (string) -> *CryptoAssembler
	pendingPackets sync.Map                      // DCID (string) -> *pendingBuffer (out-of-order packets)
	dcidAliases    sync.Map                      // Server SCID (string) -> original DCID (string)
	clientSessions sync.Map                      // Client address (string) -> original DCID (string)
	workerPool     *WorkerPool
	ctx            context.Context
	cancel         context.CancelFunc

	// DCID length tracking for Short Header parsing
	dcidLengths   map[int]struct{}
	dcidLengthsMu sync.RWMutex
}

const defaultSessionTimeout = 600 // 10 minutes in seconds

// New creates a new proxy instance.
func New(listenAddr string, chain *handler.Chain) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		listenAddr:  listenAddr,
		dcidLengths: make(map[int]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
	p.chain.Store(chain)
	p.sessionTimeout.Store(defaultSessionTimeout)
	return p
}

// SetSessionTimeout updates the idle session timeout (atomic, hot-reload safe).
// timeout is in seconds. If <= 0, uses default (600 seconds).
func (p *Proxy) SetSessionTimeout(seconds int) {
	if seconds <= 0 {
		seconds = defaultSessionTimeout
	}
	p.sessionTimeout.Store(int64(seconds))
}

// ReloadChain atomically replaces the handler chain.
// Existing sessions continue with their established connections.
func (p *Proxy) ReloadChain(chain *handler.Chain) {
	p.chain.Store(chain)
}

// Run starts the proxy server.
func (p *Proxy) Run() error {
	// Start coarse clock for efficient session activity tracking
	handler.StartCoarseClock(p.ctx)

	addr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	p.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer p.conn.Close()

	log.Printf("[proxy] listening on %s", p.listenAddr)
	log.Printf("[proxy] handler chain: %v", p.handlerNames())
	log.Printf("[proxy] session timeout: %ds", p.sessionTimeout.Load())

	// Start worker pool (bounded goroutines instead of unbounded per-packet)
	// Note: workerPool.Stop() is called in Stop() for proper graceful shutdown
	p.workerPool = NewWorkerPool(0, 0, p.handlePacket)
	p.workerPool.Start()

	// Start session cleanup goroutine
	go p.cleanupSessions()

	for {
		select {
		case <-p.ctx.Done():
			return nil
		default:
		}

		// Get buffer from pool (eliminates per-packet allocation)
		buf := handler.GetBuffer()

		p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := p.conn.ReadFromUDP(*buf)
		if err != nil {
			handler.PutBuffer(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		// Submit to worker pool (non-blocking with backpressure)
		// Buffer is returned to pool by worker after processing
		if !p.workerPool.Submit(WorkItem{
			ClientAddr: clientAddr,
			Packet:     (*buf)[:n],
			Buffer:     buf,
		}) {
			// Queue full - packet already dropped, buffer returned by Submit
		}
	}
}

// handlePacket processes an incoming UDP packet.
// Uses QUIC Connection ID (DCID) for session lookup instead of IP:Port.
// This enables Connection Migration (RFC 9000 Section 9).
func (p *Proxy) handlePacket(clientAddr *net.UDPAddr, packet []byte) {
	// DEBUG: Log packet reception
	debug.Printf(" received %d bytes from %s, first byte: 0x%02x", len(packet), clientAddr, packet[0])

	pktType := ClassifyPacket(packet)
	debug.Printf(" packet type: %s", pktType)

	// 1. Try to find existing session by DCID (with client address fallback)
	ctx, dcid := p.findSession(packet, pktType, clientAddr)
	if ctx != nil {
		// Connection Migration: update client address if changed (atomic)
		currentAddr := ctx.Session.ClientAddr()
		if !currentAddr.IP.Equal(clientAddr.IP) || currentAddr.Port != clientAddr.Port {
			log.Printf("[proxy] connection migration: %s -> %s (DCID=%x)",
				currentAddr, clientAddr, ctx.Session.DCID)
			ctx.Session.SetClientAddr(clientAddr)

			// Update clientSessions mapping for the new address
			dcidKey := string(ctx.Session.DCID)
			oldKey := currentAddr.String()
			newKey := clientAddr.String()
			p.clientSessions.Delete(oldKey)
			p.clientSessions.Store(newKey, dcidKey)
		}

		// Forward packet through handler chain
		result := p.chain.Load().OnPacket(ctx, packet, handler.Inbound)
		if result.Action == handler.Drop && result.Error != nil {
			log.Printf("[proxy] packet dropped: %v", result.Error)
		}
		return
	}

	// 2. No session found - only Initial packets can create new sessions
	if pktType != PacketInitial {
		// Buffer 0-RTT and Handshake packets that arrived before Initial
		if pktType == PacketZeroRTT || pktType == PacketHandshake {
			if dcid == nil {
				dcid, _ = ExtractDCID(packet, 0)
			}
			if dcid != nil {
				p.bufferPendingPacket(string(dcid), packet)
			}
		}
		return
	}

	// Extract DCID for assembler key
	if dcid == nil {
		var err error
		dcid, err = ExtractDCID(packet, 0)
		if err != nil {
			return
		}
	}
	dcidKey := string(dcid)

	// 3. Try to parse ClientHello from Initial packet
	assemblerVal, loaded := p.assemblers.LoadOrStore(dcidKey, NewCryptoAssembler())
	assembler := assemblerVal.(*CryptoAssembler)

	// Check for expired assembler
	if loaded && assembler.IsExpired() {
		p.assemblers.Delete(dcidKey)
		assembler = NewCryptoAssembler()
		p.assemblers.Store(dcidKey, assembler)
	}

	// If assembler is complete, we already have the ClientHello
	if assembler.IsComplete() {
		return
	}

	// Extract and add CRYPTO frames from this packet
	frames, err := ExtractCryptoFramesFromPacket(packet)
	if err != nil {
		debug.Printf(" CRYPTO extraction failed: %v", err)
	} else {
		debug.Printf(" extracted %d CRYPTO frames", len(frames))
		for _, f := range frames {
			assembler.AddFrame(f.Offset, f.Data)
		}
	}

	// Try to parse ClientHello from assembled data
	hello := assembler.TryParse()
	if hello == nil {
		debug.Printf(" TryParse returned nil (not enough data yet)")
		return
	}
	debug.Printf(" parsed ClientHello: SNI=%q ALPN=%v", hello.SNI, hello.ALPNProtocols)

	// Clean up assembler
	p.assemblers.Delete(dcidKey)

	log.Printf("[proxy] new connection: SNI=%q DCID=%x", hello.SNI, dcid)

	// Create context with DCID
	newCtx := &handler.Context{
		ClientAddr:    clientAddr,
		InitialPacket: packet,
		Hello:         hello,
		ProxyConn:     p.conn,
	}
	// Set session count for rate limiters
	newCtx.Set("_session_count", p.sessionCount.Load())

	// Set callback to learn server's SCID(s) from response packets
	// This enables routing subsequent client packets that use server's CID
	newCtx.OnServerPacket = func(packet []byte) {
		p.learnServerSCID(dcidKey, newCtx, packet)
	}

	// Process through handler chain
	result := p.chain.Load().OnConnect(newCtx)
	if result.Action == handler.Drop {
		if result.Error != nil {
			log.Printf("[proxy] connection dropped: %v", result.Error)
		}
		return
	}

	if result.Action == handler.Handled && newCtx.Session != nil {
		// Store DCID in session for future lookups
		newCtx.Session.DCID = make([]byte, len(dcid))
		copy(newCtx.Session.DCID, dcid)

		// Register DCID length for Short Header parsing
		p.registerDCIDLength(len(dcid))

		// Store session by DCID
		p.storeSession(dcidKey, newCtx)

		// Also store by client address for fallback lookup
		// (handles cases where client uses CIDs we don't know about)
		clientKey := clientAddr.String()
		p.clientSessions.Store(clientKey, dcidKey)

		// Flush any packets that arrived before this Initial (out-of-order)
		p.flushPendingPackets(dcidKey, newCtx)

		// Set DropSession callback for immediate session termination by handlers
		newCtx.DropSession = func() {
			p.chain.Load().OnDisconnect(newCtx)
			p.deleteSession(dcidKey)
		}
	}
}

// findSession looks up a session by DCID.
// For Long Header packets, DCID is extracted directly.
// For Short Header packets, tries all known DCID lengths.
// Also checks dcidAliases for server's SCID -> original DCID mapping.
// Falls back to client address lookup if DCID-based lookups fail.
func (p *Proxy) findSession(packet []byte, pktType PacketType, clientAddr *net.UDPAddr) (*handler.Context, []byte) {
	if pktType == PacketShortHeader {
		// Short Header: try all known DCID lengths (longest first to avoid prefix collisions)
		p.dcidLengthsMu.RLock()
		lengths := make([]int, 0, len(p.dcidLengths))
		for l := range p.dcidLengths {
			lengths = append(lengths, l)
		}
		p.dcidLengthsMu.RUnlock()
		sort.Sort(sort.Reverse(sort.IntSlice(lengths)))

		for _, dcidLen := range lengths {
			dcid, err := ExtractDCID(packet, dcidLen)
			if err != nil {
				continue
			}
			dcidKey := string(dcid)

			// Direct lookup
			if val, ok := p.sessions.Load(dcidKey); ok {
				return val.(*handler.Context), dcid
			}

			// Alias lookup (server's SCID -> original DCID)
			if originalKey, ok := p.dcidAliases.Load(dcidKey); ok {
				if val, ok := p.sessions.Load(originalKey.(string)); ok {
					return val.(*handler.Context), dcid
				}
			}
		}

		// Fallback: lookup by client address for Short Header packets too
		// This is needed when server issues NEW_CONNECTION_ID in encrypted frames
		if clientAddr != nil {
			clientKey := clientAddr.String()
			if originalDCID, ok := p.clientSessions.Load(clientKey); ok {
				debug.Printf(" findSession (short): trying client address fallback (%s)", clientKey)
				if val, ok := p.sessions.Load(originalDCID.(string)); ok {
					debug.Printf(" findSession (short): found session via client address")
					return val.(*handler.Context), nil
				}
			}
		}

		return nil, nil
	}

	// Long Header: DCID length is in packet
	dcid, err := ExtractDCID(packet, 0)
	if err != nil {
		debug.Printf(" findSession: failed to extract DCID: %v", err)
		return nil, nil
	}
	dcidKey := string(dcid)

	debug.Printf(" findSession: DCID=%x (len=%d)", dcid, len(dcid))

	// Direct lookup
	if val, ok := p.sessions.Load(dcidKey); ok {
		debug.Printf(" findSession: found via direct lookup")
		return val.(*handler.Context), dcid
	}

	// Alias lookup (server's SCID -> original DCID)
	if originalKey, ok := p.dcidAliases.Load(dcidKey); ok {
		debug.Printf(" findSession: found alias -> %x", originalKey.(string))
		if val, ok := p.sessions.Load(originalKey.(string)); ok {
			debug.Printf(" findSession: found session via alias")
			return val.(*handler.Context), dcid
		}
		debug.Printf(" findSession: alias found but session not found")
	} else {
		debug.Printf(" findSession: no alias found for DCID")
	}

	// Fallback: lookup by client address
	// This handles cases where client uses Connection IDs we don't know about
	// (e.g., NEW_CONNECTION_ID issued by server in encrypted frames)
	if clientAddr != nil {
		clientKey := clientAddr.String()
		if originalDCID, ok := p.clientSessions.Load(clientKey); ok {
			debug.Printf(" findSession: trying client address fallback (%s)", clientKey)
			if val, ok := p.sessions.Load(originalDCID.(string)); ok {
				debug.Printf(" findSession: found session via client address")
				return val.(*handler.Context), dcid
			}
		}
	}

	return nil, dcid
}

// registerDCIDLength adds a DCID length to the known lengths.
func (p *Proxy) registerDCIDLength(length int) {
	p.dcidLengthsMu.Lock()
	if p.dcidLengths == nil {
		p.dcidLengths = make(map[int]struct{})
	}
	p.dcidLengths[length] = struct{}{}
	p.dcidLengthsMu.Unlock()
}

// learnServerSCID extracts server's SCID(s) from a Long Header response datagram
// and registers them as aliases for the original DCID.
// This enables routing subsequent client packets that use server's CID as DCID.
// Handles coalesced packets where Initial and Handshake may have different SCIDs.
func (p *Proxy) learnServerSCID(originalDCID string, ctx *handler.Context, datagram []byte) {
	// Debug: show both DCID and SCID in the packet
	if dcid, scid, err := ExtractDCIDAndSCID(datagram); err == nil {
		debug.Printf(" learnServerSCID: packet DCID=%x, SCID=%x (datagram %d bytes)", dcid, scid, len(datagram))
		// Hex dump first 20 bytes for debugging
		hexDump := datagram[:min(20, len(datagram))]
		debug.Printf(" learnServerSCID: first 20 bytes: % x", hexDump)
	}

	// Extract all SCIDs from potentially coalesced packets
	scids := ExtractAllSCIDs(datagram)

	for _, scid := range scids {
		scidKey := string(scid)
		if scidKey == originalDCID {
			continue // Same as original, no need for alias
		}

		// Check if we already have this alias (avoid duplicate logging)
		if _, exists := p.dcidAliases.Load(scidKey); exists {
			continue
		}

		// Store alias: server's SCID -> original DCID
		p.dcidAliases.Store(scidKey, originalDCID)

		// Track SCID length for Short Header parsing
		p.registerDCIDLength(len(scid))

		log.Printf("[proxy] learned server SCID=%x for session (original DCID=%s)", scid, originalDCID[:min(8, len(originalDCID))])
	}
}

// Stop stops the proxy server gracefully.
func (p *Proxy) Stop() {
	// 1. Signal shutdown to stop accepting new packets
	p.cancel()

	// 2. Close listener (no new packets will be received)
	if p.conn != nil {
		p.conn.Close()
	}

	// 3. Drain worker pool - wait for in-flight packets to finish
	if p.workerPool != nil {
		p.workerPool.Stop()
	}

	// 4. Cleanup all sessions (now safe - no more packet processing)
	p.sessions.Range(func(key, value any) bool {
		ctx := value.(*handler.Context)
		p.chain.Load().OnDisconnect(ctx)
		p.deleteSession(key.(string))
		return true
	})
}

// cleanupSessions periodically removes stale sessions and expired assemblers.
func (p *Proxy) cleanupSessions() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			// Cleanup idle sessions
			timeout := time.Duration(p.sessionTimeout.Load()) * time.Second
			p.sessions.Range(func(key, value any) bool {
				ctx := value.(*handler.Context)
				if ctx.Session != nil {
					if ctx.Session.IdleDuration() > timeout {
						log.Printf("[proxy] cleaning up idle session: %s (idle %v)", key, ctx.Session.IdleDuration())
						p.chain.Load().OnDisconnect(ctx)
						p.deleteSession(key.(string))
					}
				}
				return true
			})

			// Cleanup expired assemblers (prevents memory leaks)
			assemblerCount := 0
			p.assemblers.Range(func(key, value any) bool {
				assembler := value.(*CryptoAssembler)
				if assembler.IsExpired() {
					p.assemblers.Delete(key)
				} else {
					assemblerCount++
				}
				return true
			})

			// Aggressive cleanup if approaching assembler limit
			if assemblerCount >= maxAssemblers*9/10 {
				log.Printf("[proxy] assembler count %d approaching limit, cleaning up", assemblerCount)
				p.assemblers.Range(func(key, value any) bool {
					assembler := value.(*CryptoAssembler)
					if assembler.IsComplete() || time.Since(assembler.createdAt) > 2*time.Second {
						p.assemblers.Delete(key)
					}
					return true
				})
			}

			// Cleanup expired pending packet buffers
			p.pendingPackets.Range(func(key, value any) bool {
				buf := value.(*pendingBuffer)
				if time.Since(buf.createdAt) > assemblerTimeout {
					p.pendingPackets.Delete(key)
				}
				return true
			})
		}
	}
}

// handlerNames returns the names of all handlers in the chain.
func (p *Proxy) handlerNames() []string {
	var names []string
	for _, h := range p.chain.Load().Handlers() {
		names = append(names, h.Name())
	}
	return names
}

// SessionCount returns the number of active sessions.
// O(1) using atomic counter instead of O(n) iteration.
func (p *Proxy) SessionCount() int {
	return int(p.sessionCount.Load())
}

// deleteSession removes a session and decrements the counter.
// Note: DCID aliases are cleaned up by timeout-based cleanup.
func (p *Proxy) deleteSession(key string) {
	if _, loaded := p.sessions.LoadAndDelete(key); loaded {
		p.sessionCount.Add(-1)

		// Clean up clientSessions mapping(s) that point to this session
		p.clientSessions.Range(func(clientKey, dcidKey any) bool {
			if dcidKey.(string) == key {
				p.clientSessions.Delete(clientKey)
			}
			return true
		})
	}
}

// storeSession stores a session with bounds checking.
// Triggers cleanup if limit is approached.
func (p *Proxy) storeSession(key string, ctx *handler.Context) {
	// O(1) increment
	count := p.sessionCount.Add(1)

	// Approaching limit - cleanup oldest 10%
	if count >= maxSessions*9/10 {
		p.cleanupOldestSessions(int(count) / 10)
	}

	p.sessions.Store(key, ctx)
}

// bufferPendingPacket stores a packet that arrived before its session existed.
// Used for out-of-order 0-RTT and Handshake packets.
func (p *Proxy) bufferPendingPacket(dcidKey string, packet []byte) {
	val, _ := p.pendingPackets.LoadOrStore(dcidKey, &pendingBuffer{
		createdAt: time.Now(),
	})
	buf := val.(*pendingBuffer)

	buf.mu.Lock()
	defer buf.mu.Unlock()

	if len(buf.packets) >= maxPendingPerDCID {
		return
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)
	buf.packets = append(buf.packets, pendingPacket{data: pktCopy})
}

// flushPendingPackets processes buffered packets after session creation.
func (p *Proxy) flushPendingPackets(dcidKey string, ctx *handler.Context) {
	val, ok := p.pendingPackets.LoadAndDelete(dcidKey)
	if !ok {
		return
	}

	buf := val.(*pendingBuffer)
	buf.mu.Lock()
	packets := buf.packets
	buf.packets = nil
	buf.mu.Unlock()

	for _, pkt := range packets {
		p.chain.Load().OnPacket(ctx, pkt.data, handler.Inbound)
	}
}

// sessionAge represents a session with its idle time for cleanup priority.
type sessionAge struct {
	key  string
	idle time.Duration
}

// sessionHeap implements heap.Interface for finding N oldest sessions.
// Uses min-heap so we can efficiently track the N largest idle times.
type sessionHeap []sessionAge

func (h sessionHeap) Len() int           { return len(h) }
func (h sessionHeap) Less(i, j int) bool { return h[i].idle < h[j].idle } // Min-heap
func (h sessionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *sessionHeap) Push(x any) {
	*h = append(*h, x.(sessionAge))
}

func (h *sessionHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// cleanupOldestSessions removes the N oldest idle sessions.
// Uses heap-based selection: O(n) instead of O(n log n) sort.
func (p *Proxy) cleanupOldestSessions(n int) {
	if n <= 0 {
		return
	}

	// Collect top N oldest using min-heap
	h := &sessionHeap{}
	heap.Init(h)

	p.sessions.Range(func(key, value any) bool {
		ctx := value.(*handler.Context)
		if ctx.Session == nil {
			return true
		}

		age := sessionAge{
			key:  key.(string),
			idle: ctx.Session.IdleDuration(),
		}

		if h.Len() < n {
			heap.Push(h, age)
		} else if age.idle > (*h)[0].idle {
			// This session is older than the youngest in our top-N
			heap.Pop(h)
			heap.Push(h, age)
		}
		return true
	})

	// Remove collected sessions
	removed := 0
	for h.Len() > 0 {
		age := heap.Pop(h).(sessionAge)
		if val, ok := p.sessions.Load(age.key); ok {
			ctx := val.(*handler.Context)
			p.chain.Load().OnDisconnect(ctx)
			p.deleteSession(age.key)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[proxy] cleaned up %d oldest sessions (approaching limit)", removed)
	}
}
