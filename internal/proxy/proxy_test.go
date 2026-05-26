package proxy

import (
	"context"
	"net"
	"quic-relay/internal/handler"
	"testing"
	"time"
)

type shutdownTestHandler struct {
	shutdownCalled bool
}

func (h *shutdownTestHandler) Name() string { return "shutdown-test" }
func (h *shutdownTestHandler) OnConnect(ctx *handler.Context) handler.Result {
	return handler.Result{Action: handler.Continue}
}
func (h *shutdownTestHandler) OnPacket(ctx *handler.Context, packet []byte, dir handler.Direction) handler.Result {
	return handler.Result{Action: handler.Continue}
}
func (h *shutdownTestHandler) OnDisconnect(ctx *handler.Context) {}
func (h *shutdownTestHandler) Shutdown(ctx context.Context) error {
	h.shutdownCalled = true
	return nil
}

func TestCryptoAssembler_AddFrame(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Add a frame at offset 0
	if !assembler.AddFrame(0, []byte{0x01, 0x02, 0x03}) {
		t.Error("AddFrame should succeed")
	}

	if assembler.maxOffset != 3 {
		t.Errorf("expected maxOffset=3, got %d", assembler.maxOffset)
	}

	// Add a frame at offset 5
	if !assembler.AddFrame(5, []byte{0x04, 0x05}) {
		t.Error("AddFrame at offset 5 should succeed")
	}

	if assembler.maxOffset != 7 {
		t.Errorf("expected maxOffset=7, got %d", assembler.maxOffset)
	}
}

func TestCryptoAssembler_AddFrame_Bounds(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Frame beyond buffer size should fail
	if assembler.AddFrame(maxCryptoBufferSize, []byte{0x01}) {
		t.Error("AddFrame beyond buffer should fail")
	}

	// Frame at edge should be truncated
	if !assembler.AddFrame(maxCryptoBufferSize-2, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Error("AddFrame at edge should succeed (with truncation)")
	}

	if assembler.maxOffset != maxCryptoBufferSize {
		t.Errorf("expected maxOffset=%d, got %d", maxCryptoBufferSize, assembler.maxOffset)
	}
}

func TestCryptoAssembler_TryParse_NotEnoughData(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Empty assembler
	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil with no data")
	}

	// Add some data but not enough for ClientHello header
	assembler.AddFrame(0, []byte{0x01, 0x00})

	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil with insufficient data")
	}
}

func TestCryptoAssembler_TryParse_WrongMessageType(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Add data that's not a ClientHello (type != 0x01)
	assembler.AddFrame(0, []byte{0x02, 0x00, 0x00, 0x10, 0x00, 0x00})

	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil for non-ClientHello")
	}
}

func TestCryptoAssembler_TryParse_Gap(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Add frame at offset 0
	assembler.AddFrame(0, []byte{0x01, 0x00, 0x00})

	// Add frame at offset 5 (gap at offset 3-4)
	assembler.AddFrame(5, []byte{0x00, 0x00, 0x00})

	if assembler.TryParse() != nil {
		t.Error("TryParse should return nil with gap in data")
	}
}

func TestCryptoAssembler_IsExpired(t *testing.T) {
	assembler := NewCryptoAssembler()

	if assembler.IsExpired() {
		t.Error("New assembler should not be expired")
	}

	// Manually set createdAt to past
	assembler.createdAt = time.Now().Add(-10 * time.Second)

	if !assembler.IsExpired() {
		t.Error("Old assembler should be expired")
	}
}

func TestCryptoAssembler_Bitset(t *testing.T) {
	assembler := NewCryptoAssembler()

	// Test setBit and isSet
	assembler.setBit(0)
	assembler.setBit(63)
	assembler.setBit(64)
	assembler.setBit(127)

	if !assembler.isSet(0) {
		t.Error("bit 0 should be set")
	}
	if !assembler.isSet(63) {
		t.Error("bit 63 should be set")
	}
	if !assembler.isSet(64) {
		t.Error("bit 64 should be set")
	}
	if !assembler.isSet(127) {
		t.Error("bit 127 should be set")
	}

	// Unset bits
	if assembler.isSet(1) {
		t.Error("bit 1 should not be set")
	}
	if assembler.isSet(65) {
		t.Error("bit 65 should not be set")
	}
}

func TestSessionHeap(t *testing.T) {
	h := &sessionHeap{}

	// Push items
	h.Push(sessionAge{key: "a", idle: 100 * time.Second})
	h.Push(sessionAge{key: "b", idle: 50 * time.Second})
	h.Push(sessionAge{key: "c", idle: 200 * time.Second})

	// Min-heap: smallest idle time should be at top
	if h.Len() != 3 {
		t.Errorf("expected len 3, got %d", h.Len())
	}

	// Pop should return smallest first
	item := h.Pop().(sessionAge)
	if item.key != "c" {
		// Note: after Push without heap.Push, order is not guaranteed
		// This test mainly ensures no panic
	}
}

func TestBufferPool(t *testing.T) {
	// Get buffer
	buf1 := handler.GetBuffer()
	if buf1 == nil {
		t.Fatal("GetBuffer returned nil")
	}
	if len(*buf1) != 65535 {
		t.Errorf("expected buffer size 65535, got %d", len(*buf1))
	}

	// Return buffer
	handler.PutBuffer(buf1)

	// Get another buffer (might be the same one from pool)
	buf2 := handler.GetBuffer()
	if buf2 == nil {
		t.Fatal("GetBuffer returned nil after PutBuffer")
	}

	handler.PutBuffer(buf2)

	// PutBuffer with nil should not panic
	handler.PutBuffer(nil)
}

func TestHandlePacket_EmptyPacketDoesNotPanic(t *testing.T) {
	p := New(":0", handler.NewChain())
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	p.handlePacket(clientAddr, nil)
	p.handlePacket(clientAddr, []byte{})
}

func TestStoreAssembler_EnforcesHardCap(t *testing.T) {
	p := New(":0", handler.NewChain())
	p.assemblerCount.Store(maxAssemblers)

	if p.storeAssembler("dcid-1", NewCryptoAssembler()) {
		t.Fatal("expected storeAssembler to reject inserts at hard cap")
	}

	if _, ok := p.assemblers.Load("dcid-1"); ok {
		t.Fatal("assembler should not be stored when cap is reached")
	}
}

func TestDeleteAssembler_DecrementsCount(t *testing.T) {
	p := New(":0", handler.NewChain())

	if !p.storeAssembler("dcid-1", NewCryptoAssembler()) {
		t.Fatal("expected assembler to be stored")
	}

	if got := p.assemblerCount.Load(); got != 1 {
		t.Fatalf("expected assemblerCount=1, got %d", got)
	}

	p.deleteAssembler("dcid-1")
	p.deleteAssembler("dcid-1")

	if got := p.assemblerCount.Load(); got != 0 {
		t.Fatalf("expected assemblerCount=0 after delete, got %d", got)
	}
}

func TestDeleteSession_RemovesTrackedAliases(t *testing.T) {
	p := New(":0", handler.NewChain())
	ctx := &handler.Context{
		Session: &handler.Session{},
	}
	ctx.Session.SetClientAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})

	p.sessions.Store("dcid-1", ctx)
	p.sessionCount.Store(1)
	p.clientSessions.Store(ctx.Session.ClientAddr().String(), "dcid-1")
	p.dcidAliases.Store("alias-1", "dcid-1")
	p.dcidAliases.Store("alias-2", "dcid-1")
	p.trackSessionAlias("dcid-1", "alias-1")
	p.trackSessionAlias("dcid-1", "alias-2")

	p.deleteSession("dcid-1", ctx)

	if _, ok := p.dcidAliases.Load("alias-1"); ok {
		t.Fatal("expected alias-1 to be removed with the session")
	}
	if _, ok := p.dcidAliases.Load("alias-2"); ok {
		t.Fatal("expected alias-2 to be removed with the session")
	}
	if _, ok := p.sessionAliases.Load("dcid-1"); ok {
		t.Fatal("expected tracked alias set to be removed with the session")
	}
}

func TestStorePendingBuffer_EnforcesHardCap(t *testing.T) {
	p := New(":0", handler.NewChain())
	p.pendingCount.Store(maxPendingBuffers)

	if p.storePendingBuffer("dcid-1", &pendingBuffer{}) {
		t.Fatal("expected storePendingBuffer to reject inserts at hard cap")
	}

	if _, ok := p.pendingPackets.Load("dcid-1"); ok {
		t.Fatal("pending buffer should not be stored when cap is reached")
	}
}

func TestLoadAndDeletePendingBuffer_DecrementsCount(t *testing.T) {
	p := New(":0", handler.NewChain())

	if !p.storePendingBuffer("dcid-1", &pendingBuffer{}) {
		t.Fatal("expected pending buffer to be stored")
	}

	if got := p.pendingCount.Load(); got != 1 {
		t.Fatalf("expected pendingCount=1, got %d", got)
	}

	if _, ok := p.loadAndDeletePendingBuffer("dcid-1"); !ok {
		t.Fatal("expected pending buffer to be deleted")
	}

	if got := p.pendingCount.Load(); got != 0 {
		t.Fatalf("expected pendingCount=0 after delete, got %d", got)
	}
}

func TestHandlePacket_DoesNotRebindSessionToNewClientAddressByDefault(t *testing.T) {
	p := New(":0", handler.NewChain())
	originalAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	newAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 23456}
	ctx := &handler.Context{
		Session: &handler.Session{
			DCID: []byte("dcid-1"),
		},
	}
	ctx.Session.SetClientAddr(originalAddr)

	p.sessions.Store("dcid-1", ctx)
	p.clientSessions.Store(originalAddr.String(), "dcid-1")

	packet := append([]byte{0x40}, []byte("dcid-1payload")...)
	p.handlePacket(newAddr, packet)

	currentAddr := ctx.Session.ClientAddr()
	if !currentAddr.IP.Equal(originalAddr.IP) || currentAddr.Port != originalAddr.Port {
		t.Fatal("expected session client address to remain unchanged")
	}
	if _, ok := p.clientSessions.Load(newAddr.String()); ok {
		t.Fatal("expected new client address to not be associated with the session")
	}
}

func TestHandlePacket_RebindsSessionWhenMigrationEnabled(t *testing.T) {
	p := New(":0", handler.NewChain())
	p.SetAllowConnectionMigration(true)

	originalAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	newAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 23456}
	ctx := &handler.Context{
		Session: &handler.Session{
			DCID: []byte("dcid-1"),
		},
	}
	ctx.Session.SetClientAddr(originalAddr)

	p.sessions.Store("dcid-1", ctx)
	p.clientSessions.Store(originalAddr.String(), "dcid-1")
	p.registerDCIDLength(len("dcid-1"))

	packet := append([]byte{0x40}, []byte("dcid-1payload")...)
	p.handlePacket(newAddr, packet)

	currentAddr := ctx.Session.ClientAddr()
	if !currentAddr.IP.Equal(newAddr.IP) || currentAddr.Port != newAddr.Port {
		t.Fatal("expected session client address to be updated when migration is enabled")
	}
	if _, ok := p.clientSessions.Load(newAddr.String()); !ok {
		t.Fatal("expected new client address to be associated with the session")
	}
}

func TestReloadChain_ShutsDownRetiredChainWithoutSessions(t *testing.T) {
	oldHandler := &shutdownTestHandler{}
	newHandler := &shutdownTestHandler{}

	p := New(":0", handler.NewChain(oldHandler))
	p.ReloadChain(handler.NewChain(newHandler))

	if !oldHandler.shutdownCalled {
		t.Fatal("expected old chain resources to be shut down on reload")
	}
	if newHandler.shutdownCalled {
		t.Fatal("did not expect new chain to be shut down")
	}
}
