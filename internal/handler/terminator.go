package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/quic-go/quic-go"
	"quic-relay/internal/debug"
)

func init() {
	Register("terminator", NewTerminatorHandler)
}

// TerminatorConfig holds configuration for the terminator handler.
type TerminatorConfig struct {
	Listen      string `json:"listen"`       // ":5521" or "auto" for ephemeral port
	Cert        string `json:"cert"`         // Path to TLS certificate
	Key         string `json:"key"`          // Path to TLS private key
	BackendMTLS bool   `json:"backend_mtls"` // Use same cert as client cert for backend mTLS
	LogPackets  int    `json:"log_packets"`  // Number of packets to log per direction (0 = disabled)
	SkipPackets int    `json:"skip_packets"` // Number of packets to skip before logging
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
	clientCert   *tls.Certificate // Client certificate for backend mTLS

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

	// Store certificate for backend mTLS if enabled
	if cfg.BackendMTLS {
		h.clientCert = &cert
		log.Printf("[terminator] backend mTLS enabled")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Accept any ALPN protocol the client offers
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   chi.SupportedProtos, // Mirror client's offered protocols
			}, nil
		},
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
	// Add client certificate for mTLS if configured
	if h.clientCert != nil {
		backendTLS.Certificates = []tls.Certificate{*h.clientCert}
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
	session := newTerminatorSession(clientConn, serverConn, h.config.LogPackets, h.config.SkipPackets)
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
	clientConn    *quic.Conn
	serverConn    *quic.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	closed        atomic.Bool
	wg            sync.WaitGroup
	clientPackets atomic.Int32 // Counter for logged client packets
	serverPackets atomic.Int32 // Counter for logged server packets
	logPackets    int          // Max packets to log per direction
	skipPackets   int          // Packets to skip before logging
}

// streamLogger buffers stream data to handle packet fragmentation.
type streamLogger struct {
	prefix      string
	counter     *atomic.Int32
	buffer      []byte
	packets     int
	maxPackets  int
	skipPackets int
	skipped     int
}

func newStreamLogger(prefix string, counter *atomic.Int32, maxPackets, skipPackets int) *streamLogger {
	return &streamLogger{
		prefix:      prefix,
		counter:     counter,
		maxPackets:  maxPackets,
		skipPackets: skipPackets,
	}
}

// processData adds data to buffer and tries to log complete packets.
func (l *streamLogger) processData(data []byte) {
	if l.maxPackets <= 0 || l.packets >= l.maxPackets {
		return // Logging disabled or limit reached
	}

	l.buffer = append(l.buffer, data...)
	beforeLen := len(l.buffer)
	l.tryLogPackets()

	// Debug: log if buffer is stuck
	if len(l.buffer) > 1024 && len(l.buffer) == beforeLen && l.packets == 0 && l.skipped < l.skipPackets {
		log.Printf("%s DEBUG: buffer stuck at %d bytes, skipped=%d, has zstd=%v",
			l.prefix, len(l.buffer), l.skipped, bytes.Contains(l.buffer[:min(len(l.buffer), 256)], zstdMagic))
	}
}

// tryLogPackets attempts to extract and log complete packets from the buffer.
func (l *streamLogger) tryLogPackets() {
	for l.packets < l.maxPackets && len(l.buffer) > 0 {
		// Determine if we should log this packet or just skip it
		shouldLog := l.skipped >= l.skipPackets

		consumed := l.tryConsumePacket(shouldLog)
		if consumed == 0 {
			break // Need more data
		}
		l.buffer = l.buffer[consumed:]

		// Skip packets before logging
		if l.skipped < l.skipPackets {
			l.skipped++
			continue
		}

		l.packets++
		l.counter.Add(1)
	}
}

const maxZstdDecodeSize = 64 * 1024 // 64KB max for zstd decode attempts

// tryConsumePacket finds a complete packet and optionally logs it.
// Returns bytes consumed, or 0 if incomplete.
func (l *streamLogger) tryConsumePacket(shouldLog bool) int {
	if len(l.buffer) < 8 {
		return 0 // Need at least header
	}

	// Look for zstd magic anywhere in the buffer
	idx := bytes.Index(l.buffer, zstdMagic)
	if idx >= 0 {
		compressed := l.buffer[idx:]

		// If buffer is too large, skip zstd decode and just consume a chunk
		if len(l.buffer) > maxZstdDecodeSize {
			// Large packet - log header + raw summary
			consumeLen := 4096
			if consumeLen > len(l.buffer) {
				consumeLen = len(l.buffer)
			}
			if shouldLog {
				log.Printf("%s packet #%d (large zstd, %d bytes buffered, consuming %d)\n",
					l.prefix, l.packets+1, len(l.buffer), consumeLen)
			}
			return consumeLen
		}

		// Try to decode (only for reasonable sizes)
		frameSize := getZstdFrameSize(compressed)
		if frameSize == 0 {
			return 0 // Need more data
		}

		// Complete frame
		totalLen := idx + frameSize
		if shouldLog {
			logPacketComplete(l.prefix, l.packets+1, l.buffer[:totalLen], idx, frameSize)
		}
		return totalLen
	}

	// No zstd magic found

	// Check if buffer looks like it might be waiting for zstd
	if len(l.buffer) >= 4096 {
		if shouldLog {
			logPacket(l.prefix, l.packets+1, l.buffer[:4096])
		}
		return 4096
	}

	// Try to determine packet boundary
	pktLen := l.findPacketBoundary()
	if pktLen > 0 && pktLen <= len(l.buffer) {
		if shouldLog {
			logPacket(l.prefix, l.packets+1, l.buffer[:pktLen])
		}
		return pktLen
	}

	// If buffer is reasonably sized, consume it
	if len(l.buffer) >= 64 && len(l.buffer) < 1024 {
		if shouldLog {
			logPacket(l.prefix, l.packets+1, l.buffer)
		}
		return len(l.buffer)
	}

	return 0 // Need more data
}

// findPacketBoundary tries to find where the current packet ends.
func (l *streamLogger) findPacketBoundary() int {
	// Look for patterns that suggest packet boundaries
	// The protocol seems to have 8-byte headers with small type values

	// Scan for potential next packet header
	for i := 8; i+8 <= len(l.buffer); i++ {
		// Check if this looks like a header (small first uint32, reasonable second)
		val1 := binary.LittleEndian.Uint32(l.buffer[i:])
		val2 := binary.LittleEndian.Uint32(l.buffer[i+4:])

		// Header heuristics: type < 256, second value < 64KB
		if val1 < 256 && val2 < 65536 && val2 > 0 {
			return i
		}
	}

	return 0
}

// getZstdFrameSize returns the total frame size, or 0 if incomplete.
// Uses binary search to find the minimum valid frame size.
func getZstdFrameSize(data []byte) int {
	if len(data) < 5 {
		return 0 // Need magic + descriptor at minimum
	}

	// Binary search for minimum valid frame size
	lo, hi := 5, len(data)
	result := 0

	for lo <= hi {
		mid := (lo + hi) / 2
		if _, err := zstdDecoder.DecodeAll(data[:mid], nil); err == nil {
			result = mid // This size works
			hi = mid - 1 // Try smaller
		} else {
			lo = mid + 1 // Need more
		}
	}

	return result
}

// logPacketComplete logs a packet with successful zstd decode.
func logPacketComplete(prefix string, num int, data []byte, zstdIdx, frameSize int) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s packet #%d (%d bytes)\n", prefix, num, len(data)))

	if zstdIdx > 0 {
		sb.WriteString(fmt.Sprintf("── Header (%d bytes) ──\n", zstdIdx))
		sb.WriteString(formatHeader(data[:zstdIdx]))
	}

	compressed := data[zstdIdx : zstdIdx+frameSize]
	if decompressed, err := zstdDecoder.DecodeAll(compressed, nil); err == nil {
		sb.WriteString(fmt.Sprintf("── Payload (zstd: %d → %d bytes) ──\n", len(compressed), len(decompressed)))
		sb.WriteString(hexDump(decompressed))
	} else {
		sb.WriteString(fmt.Sprintf("── Payload (zstd decode failed: %v) ──\n", err))
		sb.WriteString(hexDump(compressed))
	}

	log.Print(sb.String())
}

func newTerminatorSession(client, server *quic.Conn, logPackets, skipPackets int) *terminatorSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &terminatorSession{
		clientConn:  client,
		serverConn:  server,
		ctx:         ctx,
		cancel:      cancel,
		logPackets:  logPackets,
		skipPackets: skipPackets,
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
	go s.bridgeBidirectional(s.clientConn, s.serverConn, true)        // Client-initiated
	go s.bridgeBidirectional(s.serverConn, s.clientConn, false)       // Server-initiated
	go s.bridgeUnidirectional(s.clientConn, s.serverConn, "[client]") // Client → Server
	go s.bridgeUnidirectional(s.serverConn, s.clientConn, "[server]") // Server → Client

	s.wg.Wait()
}

func (s *terminatorSession) bridgeBidirectional(src, dst *quic.Conn, srcIsClient bool) {
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
		go s.copyBidirectionalStream(srcStream, dstStream, srcIsClient)
	}
}

func (s *terminatorSession) bridgeUnidirectional(src, dst *quic.Conn, prefix string) {
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
		go s.copyUnidirectionalStream(srcStream, dstStream, prefix)
	}
}

func (s *terminatorSession) copyBidirectionalStream(src, dst *quic.Stream, srcIsClient bool) {
	defer s.wg.Done()
	defer src.Close()
	defer dst.Close()

	debug.Printf(" copyBidirectionalStream: bridging stream %d <-> %d", src.StreamID(), dst.StreamID())

	srcPrefix := "[server]"
	dstPrefix := "[client]"
	if srcIsClient {
		srcPrefix = "[client]"
		dstPrefix = "[server]"
	}

	done := make(chan struct{}, 2)

	// src → dst
	go func() {
		n, err := s.copyWithLog(dst, src, srcPrefix)
		debug.Printf(" stream %d -> %d: copied %d bytes, err=%v", src.StreamID(), dst.StreamID(), n, err)
		dst.Close() // Signal write-end closed (sends FIN)
		done <- struct{}{}
	}()

	// dst → src
	go func() {
		n, err := s.copyWithLog(src, dst, dstPrefix)
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

func (s *terminatorSession) copyUnidirectionalStream(src *quic.ReceiveStream, dst *quic.SendStream, prefix string) {
	defer s.wg.Done()
	defer dst.Close()

	s.copyWithLog(dst, src, prefix)
}

// zstd magic number: 0xFD2FB528
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// Shared zstd decoder (thread-safe, reusable)
var zstdDecoder, _ = zstd.NewReader(nil)

// copyWithLog copies data from src to dst while logging the first 5 packets per direction.
func (s *terminatorSession) copyWithLog(dst io.Writer, src io.Reader, prefix string) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	counter := &s.serverPackets
	if prefix == "[client]" {
		counter = &s.clientPackets
	}

	logger := newStreamLogger(prefix, counter, s.logPackets, s.skipPackets)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			logger.processData(buf[:n])
			nw, werr := dst.Write(buf[:n])
			total += int64(nw)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// logPacket analyzes and logs a packet, decompressing zstd if found.
func logPacket(prefix string, num int, data []byte) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s packet #%d (%d bytes)\n", prefix, num, len(data)))

	// Find zstd magic in packet
	if idx := bytes.Index(data, zstdMagic); idx >= 0 && idx < 32 {
		// Header before zstd
		if idx > 0 {
			sb.WriteString(fmt.Sprintf("── Header (%d bytes) ──\n", idx))
			sb.WriteString(formatHeader(data[:idx]))
		}

		// Decompress zstd payload
		compressed := data[idx:]
		if decompressed, err := zstdDecoder.DecodeAll(compressed, nil); err == nil {
			sb.WriteString(fmt.Sprintf("── Payload (zstd: %d → %d bytes) ──\n", len(compressed), len(decompressed)))
			sb.WriteString(hexDump(decompressed))
		} else {
			sb.WriteString(fmt.Sprintf("── Payload (zstd decode failed: %v) ──\n", err))
			sb.WriteString(hexDump(compressed))
		}
	} else {
		// No zstd, dump raw
		sb.WriteString(hexDump(data))
	}

	log.Print(sb.String())
}

// formatHeader formats the packet header as labeled uint32 fields.
func formatHeader(data []byte) string {
	var sb strings.Builder
	for i := 0; i+4 <= len(data); i += 4 {
		val := binary.LittleEndian.Uint32(data[i:])
		sb.WriteString(fmt.Sprintf("  [%d] 0x%08x (%d)\n", i/4, val, val))
	}
	// Trailing bytes
	if rem := len(data) % 4; rem > 0 {
		sb.WriteString(fmt.Sprintf("  ... %x\n", data[len(data)-rem:]))
	}
	return sb.String()
}

// hexDump formats bytes as hex + ASCII.
func hexDump(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		sb.WriteString(fmt.Sprintf("%04x  ", i))
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				sb.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// Close closes the session and both connections.
func (s *terminatorSession) Close() {
	if !s.closed.Swap(true) {
		s.cancel()
		s.clientConn.CloseWithError(0, "session closed")
		s.serverConn.CloseWithError(0, "session closed")
	}
}
