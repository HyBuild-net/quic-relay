package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
)

func init() {
	Register("simple-router", NewStaticHandler)
}

// StaticConfig is the configuration for the static handler.
type StaticConfig struct {
	Backend  string   `json:"backend,omitempty"`  // Single backend
	Backends []string `json:"backends,omitempty"` // Multiple backends (load balancing)
}

// StaticHandler routes all connections to a fixed backend or load-balances across multiple.
type StaticHandler struct {
	backends []string
	counter  atomic.Uint64
}

// NewStaticHandler creates a new static handler.
func NewStaticHandler(raw json.RawMessage) (Handler, error) {
	var cfg StaticConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("invalid static config: %w", err)
		}
	}

	var backends []string
	if len(cfg.Backends) > 0 {
		backends = cfg.Backends
	} else if cfg.Backend != "" {
		backends = []string{cfg.Backend}
	} else if env := os.Getenv("QUIC_RELAY_BACKEND"); env != "" {
		backends = []string{env}
	} else {
		return nil, fmt.Errorf("simple-router requires 'backend', 'backends' config or QUIC_RELAY_BACKEND env")
	}

	return &StaticHandler{backends: backends}, nil
}

// Name returns the handler name.
func (h *StaticHandler) Name() string {
	return "simple-router"
}

// OnConnect sets the backend address in context (round-robin if multiple).
func (h *StaticHandler) OnConnect(ctx *Context) Result {
	idx := h.counter.Add(1) - 1
	backend := h.backends[idx%uint64(len(h.backends))]
	ctx.Set("backend", backend)
	return Result{Action: Continue}
}

// OnPacket passes through.
func (h *StaticHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect does nothing.
func (h *StaticHandler) OnDisconnect(ctx *Context) {}
