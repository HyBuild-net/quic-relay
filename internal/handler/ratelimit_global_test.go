package handler

import (
	"encoding/json"
	"testing"
)

func TestRateLimitGlobal_RequiresConfig(t *testing.T) {
	_, err := NewRateLimitGlobalHandler(nil)
	if err == nil {
		t.Error("expected error for missing config")
	}

	_, err = NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 0}`))
	if err == nil {
		t.Error("expected error for max_parallel_connections = 0")
	}

	_, err = NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": -1}`))
	if err == nil {
		t.Error("expected error for negative max_parallel_connections")
	}
}

func TestRateLimitGlobal_AllowsUnderLimit(t *testing.T) {
	h, err := NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 10}`))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := &Context{}
	ctx.Set("_session_count", int64(5)) // 5 active, limit is 10

	result := h.OnConnect(ctx)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v (error: %v)", result.Action, result.Error)
	}
}

func TestRateLimitGlobal_AllowsAtLimit(t *testing.T) {
	h, err := NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 10}`))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := &Context{}
	ctx.Set("_session_count", int64(9)) // 9 active, limit is 10 -> this would be the 10th

	result := h.OnConnect(ctx)
	if result.Action != Continue {
		t.Errorf("expected Continue at limit-1, got %v (error: %v)", result.Action, result.Error)
	}
}

func TestRateLimitGlobal_DropsOverLimit(t *testing.T) {
	h, err := NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 10}`))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := &Context{}
	ctx.Set("_session_count", int64(10)) // 10 active, limit is 10 -> reject new

	result := h.OnConnect(ctx)
	if result.Action != Drop {
		t.Errorf("expected Drop when at limit, got %v", result.Action)
	}
	if result.Error == nil {
		t.Error("expected error message when dropping")
	}
}

func TestRateLimitGlobal_DropsWellOverLimit(t *testing.T) {
	h, err := NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 10}`))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := &Context{}
	ctx.Set("_session_count", int64(100)) // way over limit

	result := h.OnConnect(ctx)
	if result.Action != Drop {
		t.Errorf("expected Drop when well over limit, got %v", result.Action)
	}
}

func TestRateLimitGlobal_OnPacketPassesThrough(t *testing.T) {
	h, err := NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 10}`))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := &Context{}
	result := h.OnPacket(ctx, []byte{0x01, 0x02, 0x03}, Inbound)
	if result.Action != Continue {
		t.Errorf("expected OnPacket to Continue, got %v", result.Action)
	}
}

func TestRateLimitGlobal_Name(t *testing.T) {
	h, err := NewRateLimitGlobalHandler(json.RawMessage(`{"max_parallel_connections": 10}`))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if h.Name() != "ratelimit-global" {
		t.Errorf("expected name 'ratelimit-global', got '%s'", h.Name())
	}
}
