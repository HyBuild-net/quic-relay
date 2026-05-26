package handler

import (
	"encoding/json"
	"fmt"
)

const (
	sessionCountKey       = "_session_count"
	sessionReservedKey    = "_session_reserved"
	reserveSessionSlotKey = "_reserve_session_slot"
)

func init() {
	Register("ratelimit-global", NewRateLimitGlobalHandler)
}

// RateLimitGlobalConfig is the configuration for the global rate limiter.
type RateLimitGlobalConfig struct {
	MaxParallelConnections int64 `json:"max_parallel_connections"`
}

// RateLimitGlobalHandler limits the total number of concurrent connections.
// It uses the proxy's session count which is set in the context before OnConnect.
type RateLimitGlobalHandler struct {
	maxParallelConnections int64
}

// NewRateLimitGlobalHandler creates a new global rate limiter handler.
func NewRateLimitGlobalHandler(raw json.RawMessage) (Handler, error) {
	var cfg RateLimitGlobalConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("invalid ratelimit-global config: %w", err)
		}
	}
	if cfg.MaxParallelConnections <= 0 {
		return nil, fmt.Errorf("ratelimit-global requires 'max_parallel_connections' > 0")
	}
	return &RateLimitGlobalHandler{maxParallelConnections: cfg.MaxParallelConnections}, nil
}

// Name returns the handler name.
func (h *RateLimitGlobalHandler) Name() string {
	return "ratelimit-global"
}

// OnConnect checks if the connection limit has been reached.
func (h *RateLimitGlobalHandler) OnConnect(ctx *Context) Result {
	if reserve, ok := GetValue[func(int64) bool](ctx, reserveSessionSlotKey); ok {
		if !reserve(h.maxParallelConnections) {
			currentCount := ctx.GetInt64(sessionCountKey)
			return Result{Action: Drop, Error: fmt.Errorf("max connections exceeded (%d/%d)", currentCount, h.maxParallelConnections)}
		}
		ctx.Set(sessionReservedKey, true)
		return Result{Action: Continue}
	}

	currentCount := ctx.GetInt64(sessionCountKey)
	if currentCount >= h.maxParallelConnections {
		return Result{Action: Drop, Error: fmt.Errorf("max connections exceeded (%d/%d)", currentCount, h.maxParallelConnections)}
	}
	return Result{Action: Continue}
}

// OnPacket passes through.
func (h *RateLimitGlobalHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect does nothing - proxy manages the session count.
func (h *RateLimitGlobalHandler) OnDisconnect(ctx *Context) {}
