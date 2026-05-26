package handler

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockHandler is a test handler that records calls.
type mockHandler struct {
	name             string
	onConnectResult  Result
	onPacketResult   Result
	connectCalled    bool
	packetCalled     bool
	disconnectCalled bool
	shutdownCalled   bool
}

func newMockHandler(name string, connectAction, packetAction Action) *mockHandler {
	return &mockHandler{
		name:            name,
		onConnectResult: Result{Action: connectAction},
		onPacketResult:  Result{Action: packetAction},
	}
}

func (h *mockHandler) Name() string { return h.name }

func (h *mockHandler) OnConnect(ctx *Context) Result {
	h.connectCalled = true
	return h.onConnectResult
}

func (h *mockHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	h.packetCalled = true
	return h.onPacketResult
}

func (h *mockHandler) OnDisconnect(ctx *Context) {
	h.disconnectCalled = true
}

func (h *mockHandler) Shutdown(ctx context.Context) error {
	h.shutdownCalled = true
	return nil
}

func TestChain_OnConnect_Continue(t *testing.T) {
	h1 := newMockHandler("h1", Continue, Continue)
	h2 := newMockHandler("h2", Handled, Continue)

	chain := NewChain(h1, h2)
	ctx := &Context{ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}

	result := chain.OnConnect(ctx)

	if !h1.connectCalled {
		t.Error("h1.OnConnect should have been called")
	}
	if !h2.connectCalled {
		t.Error("h2.OnConnect should have been called")
	}
	if result.Action != Handled {
		t.Errorf("expected Handled, got %v", result.Action)
	}
}

func TestChain_OnConnect_Drop(t *testing.T) {
	h1 := newMockHandler("h1", Drop, Continue)
	h2 := newMockHandler("h2", Handled, Continue)

	chain := NewChain(h1, h2)
	ctx := &Context{ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}

	result := chain.OnConnect(ctx)

	if !h1.connectCalled {
		t.Error("h1.OnConnect should have been called")
	}
	if h2.connectCalled {
		t.Error("h2.OnConnect should NOT have been called after Drop")
	}
	if result.Action != Drop {
		t.Errorf("expected Drop, got %v", result.Action)
	}
}

func TestChain_OnConnect_EmptyChain(t *testing.T) {
	chain := NewChain()
	ctx := &Context{ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}

	result := chain.OnConnect(ctx)

	if result.Action != Drop {
		t.Errorf("empty chain should return Drop, got %v", result.Action)
	}
}

func TestChain_OnPacket(t *testing.T) {
	h1 := newMockHandler("h1", Continue, Continue)
	h2 := newMockHandler("h2", Continue, Handled)

	chain := NewChain(h1, h2)
	ctx := &Context{ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}
	packet := []byte{0x01, 0x02, 0x03}

	result := chain.OnPacket(ctx, packet, Inbound)

	if !h1.packetCalled {
		t.Error("h1.OnPacket should have been called")
	}
	if !h2.packetCalled {
		t.Error("h2.OnPacket should have been called")
	}
	if result.Action != Handled {
		t.Errorf("expected Handled, got %v", result.Action)
	}
}

func TestChain_OnDisconnect(t *testing.T) {
	h1 := newMockHandler("h1", Continue, Continue)
	h2 := newMockHandler("h2", Continue, Continue)

	chain := NewChain(h1, h2)
	ctx := &Context{ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}

	chain.OnDisconnect(ctx)

	if !h1.disconnectCalled {
		t.Error("h1.OnDisconnect should have been called")
	}
	if !h2.disconnectCalled {
		t.Error("h2.OnDisconnect should have been called")
	}
}

func TestChain_Handlers(t *testing.T) {
	h1 := newMockHandler("h1", Continue, Continue)
	h2 := newMockHandler("h2", Continue, Continue)

	chain := NewChain(h1, h2)
	handlers := chain.Handlers()

	if len(handlers) != 2 {
		t.Errorf("expected 2 handlers, got %d", len(handlers))
	}
	if handlers[0].Name() != "h1" {
		t.Errorf("expected h1, got %s", handlers[0].Name())
	}
	if handlers[1].Name() != "h2" {
		t.Errorf("expected h2, got %s", handlers[1].Name())
	}
}

func TestContext_SetGet(t *testing.T) {
	ctx := &Context{}

	ctx.Set("key1", "value1")
	ctx.Set("key2", 42)
	ctx.Set("key3", true)

	if v := ctx.GetString("key1"); v != "value1" {
		t.Errorf("expected value1, got %s", v)
	}
	if v := ctx.GetInt("key2"); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
	if v := ctx.GetBool("key3"); v != true {
		t.Errorf("expected true, got %v", v)
	}

	// Non-existent key
	if v := ctx.GetString("nonexistent"); v != "" {
		t.Errorf("expected empty string, got %s", v)
	}

	// Wrong type
	if v := ctx.GetInt("key1"); v != 0 {
		t.Errorf("expected 0 for wrong type, got %d", v)
	}
}

func TestSession_Touch(t *testing.T) {
	// Initialize coarse clock for test
	coarseTime.Store(time.Now().Unix())

	session := &Session{
		ID: 1,
	}
	// LastActivity starts at zero value

	session.Touch()

	if session.LastActivity.Load() == 0 {
		t.Error("Touch should update LastActivity")
	}
}

func TestSession_IdleDuration(t *testing.T) {
	// Initialize coarse clock for test
	coarseTime.Store(time.Now().Unix())

	session := &Session{
		ID: 1,
	}
	session.Touch()

	idle := session.IdleDuration()

	// Should be very small since we just touched it
	if idle.Seconds() > 1 {
		t.Errorf("expected idle < 1s, got %v", idle)
	}
}

// --- GetValue Generic Tests ---

func TestGetValue_String(t *testing.T) {
	ctx := &Context{}
	ctx.Set("backend", "localhost:4433")

	// Type-safe retrieval
	backend, ok := GetValue[string](ctx, "backend")
	if !ok {
		t.Error("expected ok=true")
	}
	if backend != "localhost:4433" {
		t.Errorf("expected localhost:4433, got %s", backend)
	}
}

func TestGetValue_Struct(t *testing.T) {
	type RateLimitInfo struct {
		Allowed    bool
		RetryAfter int
	}

	ctx := &Context{}
	ctx.Set("rateLimit", &RateLimitInfo{Allowed: true, RetryAfter: 60})

	// Type-safe struct retrieval
	info, ok := GetValue[*RateLimitInfo](ctx, "rateLimit")
	if !ok {
		t.Error("expected ok=true")
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if !info.Allowed {
		t.Error("expected Allowed=true")
	}
	if info.RetryAfter != 60 {
		t.Errorf("expected RetryAfter=60, got %d", info.RetryAfter)
	}
}

func TestGetValue_WrongType(t *testing.T) {
	ctx := &Context{}
	ctx.Set("key", "string value")

	// Try to get as int - should fail
	val, ok := GetValue[int](ctx, "key")
	if ok {
		t.Error("expected ok=false for wrong type")
	}
	if val != 0 {
		t.Errorf("expected zero value, got %d", val)
	}
}

func TestGetValue_NotFound(t *testing.T) {
	ctx := &Context{}

	val, ok := GetValue[string](ctx, "nonexistent")
	if ok {
		t.Error("expected ok=false for missing key")
	}
	if val != "" {
		t.Errorf("expected empty string, got %s", val)
	}
}

func TestContext_Concurrent(t *testing.T) {
	ctx := &Context{}
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			ctx.Set("counter", i)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			ctx.Get("counter")
			ctx.GetString("counter")
			GetValue[int](ctx, "counter")
		}
		done <- true
	}()

	// Wait for both
	<-done
	<-done

	// If we get here without race detector complaints, test passes
}

func TestLogSNIHandler_Name(t *testing.T) {
	h, err := NewLogSNIHandler(nil)
	if err != nil {
		t.Fatalf("failed to create logsni handler: %v", err)
	}

	if h.Name() != "logsni" {
		t.Fatalf("expected handler name logsni, got %q", h.Name())
	}
}

func TestChain_Shutdown(t *testing.T) {
	h1 := newMockHandler("h1", Continue, Continue)
	h2 := newMockHandler("h2", Continue, Continue)

	chain := NewChain(h1, h2)
	if err := chain.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected shutdown error: %v", err)
	}

	if !h1.shutdownCalled {
		t.Fatal("expected h1 shutdown to be called")
	}
	if !h2.shutdownCalled {
		t.Fatal("expected h2 shutdown to be called")
	}
}
