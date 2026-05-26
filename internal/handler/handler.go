package handler

import "context"

// Action represents the result action from a handler.
type Action int

const (
	// Continue passes control to the next handler in the chain.
	Continue Action = iota
	// Handled indicates the handler has fully processed the request (e.g., forwarded).
	Handled
	// Drop discards the connection/packet.
	Drop
)

// Result is returned by handler methods.
type Result struct {
	Action Action
	Error  error
}

// Direction indicates the packet flow direction.
type Direction int

const (
	// Inbound represents packets from client to proxy.
	Inbound Direction = iota
	// Outbound represents packets from backend to client.
	Outbound
)

// Handler is the interface that all handlers must implement.
type Handler interface {
	// Name returns the handler name for logging and config.
	Name() string

	// OnConnect is called when a new connection is established (first packet with ClientHello).
	// Handlers can:
	// - Log and collect metrics (return Continue)
	// - Set routing info in ctx.Values (return Continue)
	// - Rate limit (return Drop)
	// - Start forwarding (return Handled)
	OnConnect(ctx *Context) Result

	// OnPacket is called for each packet after the initial connection.
	// Handlers can:
	// - Inspect or modify packets (return Continue)
	// - Drop packets (return Drop)
	// - Forward packets (return Handled)
	OnPacket(ctx *Context, packet []byte, dir Direction) Result

	// OnDisconnect is called when the connection ends. Used for cleanup.
	OnDisconnect(ctx *Context)
}

// ShutdownHandler is implemented by handlers that own background resources
// which should be released on proxy reload or shutdown.
type ShutdownHandler interface {
	Shutdown(ctx context.Context) error
}

// Chain executes handlers in sequence.
type Chain struct {
	handlers []Handler
}

// NewChain creates a new handler chain.
func NewChain(handlers ...Handler) *Chain {
	return &Chain{handlers: handlers}
}

// OnConnect processes a new connection through the chain.
// Stops at the first Handled or Drop result.
func (c *Chain) OnConnect(ctx *Context) Result {
	for _, h := range c.handlers {
		result := h.OnConnect(ctx)
		if result.Action != Continue {
			return result
		}
	}
	// No handler handled the connection
	return Result{Action: Drop}
}

// OnPacket processes a packet through the chain.
func (c *Chain) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	for _, h := range c.handlers {
		result := h.OnPacket(ctx, packet, dir)
		if result.Action != Continue {
			return result
		}
	}
	return Result{Action: Drop}
}

// OnDisconnect notifies all handlers of disconnection.
func (c *Chain) OnDisconnect(ctx *Context) {
	for _, h := range c.handlers {
		h.OnDisconnect(ctx)
	}
}

// Handlers returns the list of handlers in the chain.
func (c *Chain) Handlers() []Handler {
	return c.handlers
}

// Shutdown releases resources owned by handlers that implement ShutdownHandler.
func (c *Chain) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, h := range c.handlers {
		shutdown, ok := h.(ShutdownHandler)
		if !ok {
			continue
		}
		if err := shutdown.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
