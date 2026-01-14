package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
)

func init() {
	Register("sni-router", NewDynamicHandler)
}

// route holds backends for a single SNI with its own round-robin counter.
type route struct {
	backends []string
	counter  atomic.Uint64
}

// next returns the next backend using round-robin.
func (r *route) next() string {
	idx := r.counter.Add(1) - 1
	return r.backends[idx%uint64(len(r.backends))]
}

// DynamicHandler routes connections based on SNI to different backends.
type DynamicHandler struct {
	routes map[string]*route
}

// NewDynamicHandler creates a new dynamic handler.
func NewDynamicHandler(raw json.RawMessage) (Handler, error) {
	// Parse as map[string]any to handle both string and []string values
	var cfg struct {
		Routes map[string]any `json:"routes"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("invalid dynamic config: %w", err)
		}
	}
	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("dynamic handler requires 'routes' config")
	}

	routes := make(map[string]*route, len(cfg.Routes))
	for sni, val := range cfg.Routes {
		var backends []string
		switch v := val.(type) {
		case string:
			backends = []string{v}
		case []any:
			backends = make([]string, len(v))
			for i, b := range v {
				s, ok := b.(string)
				if !ok {
					return nil, fmt.Errorf("invalid backend for SNI %s: expected string", sni)
				}
				backends[i] = s
			}
		default:
			return nil, fmt.Errorf("invalid backend for SNI %s: expected string or array", sni)
		}
		if len(backends) == 0 {
			return nil, fmt.Errorf("empty backends for SNI %s", sni)
		}
		routes[sni] = &route{backends: backends}
	}

	return &DynamicHandler{routes: routes}, nil
}

// Name returns the handler name.
func (h *DynamicHandler) Name() string {
	return "sni-router"
}

// OnConnect sets the backend address based on SNI.
func (h *DynamicHandler) OnConnect(ctx *Context) Result {
	if ctx.Hello == nil {
		return Result{Action: Drop, Error: errors.New("no ClientHello")}
	}

	sni := ctx.Hello.SNI
	if sni == "" {
		return Result{Action: Drop, Error: errors.New("no SNI")}
	}

	r, ok := h.routes[sni]
	if !ok {
		return Result{Action: Drop, Error: fmt.Errorf("unknown SNI: %s", sni)}
	}

	ctx.Set("backend", r.next())
	return Result{Action: Continue}
}

// OnPacket passes through.
func (h *DynamicHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect does nothing.
func (h *DynamicHandler) OnDisconnect(ctx *Context) {}
