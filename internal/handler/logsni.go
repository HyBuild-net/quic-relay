package handler

import (
	"encoding/json"
	"log"
	"strconv"
)

func init() {
	Register("logsni", NewLogSNIHandler)
}

// LogSNIHandler logs the SNI for each new connection.
type LogSNIHandler struct{}

// NewLogSNIHandler creates a new logsni handler.
func NewLogSNIHandler(_ json.RawMessage) (Handler, error) {
	return &LogSNIHandler{}, nil
}

// Name returns the handler name.
func (h *LogSNIHandler) Name() string { return "logsni" }

// OnConnect logs the SNI.
func (h *LogSNIHandler) OnConnect(ctx *Context) Result {
	sni := ""
	if ctx.Hello != nil {
		sni = ctx.Hello.SNI
	}
	log.Printf("[sni] %s", strconv.QuoteToASCII(sni))
	return Result{Action: Continue}
}

// OnPacket does nothing.
func (h *LogSNIHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect does nothing.
func (h *LogSNIHandler) OnDisconnect(ctx *Context) {}
