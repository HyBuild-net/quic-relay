package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"

	terminator "quic-terminator"
)

func init() {
	Register("terminator", NewTerminatorHandler)
}

// TerminatorCertConfig holds TLS config for a certificate.
type TerminatorCertConfig struct {
	Cert        string `json:"cert"`                   // Path to TLS certificate
	Key         string `json:"key"`                    // Path to TLS private key
	BackendMTLS *bool  `json:"backend_mtls,omitempty"` // Use cert as client cert for backend mTLS (default: true)
}

// TerminatorCertsConfig groups all certificate configurations.
type TerminatorCertsConfig struct {
	Default *TerminatorCertConfig            `json:"default"` // Fallback certificate
	Targets map[string]*TerminatorCertConfig `json:"targets"` // Backend address → cert config
}

// TerminatorHandlerConfig holds configuration for the terminator handler.
type TerminatorHandlerConfig struct {
	Listen string `json:"listen"` // ":5521" or "auto" for ephemeral port

	// Certificate configurations
	Certs *TerminatorCertsConfig `json:"certs"`

	// Debug enables packet parsing and logging
	Debug            bool `json:"debug"`
	DebugPacketLimit int  `json:"debug_packet_limit"` // Max packets to log per stream (0 = unlimited)
}

// TerminatorHandler wraps the terminator library as a HyProxy handler.
type TerminatorHandler struct {
	term *terminator.Terminator
}

// NewTerminatorHandler creates a new terminator handler.
func NewTerminatorHandler(raw json.RawMessage) (Handler, error) {
	var cfg TerminatorHandlerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	// Convert handler config to terminator config
	termCfg := terminator.Config{
		Listen:           cfg.Listen,
		Debug:            cfg.Debug,
		DebugPacketLimit: cfg.DebugPacketLimit,
	}

	// Convert certificate configs
	if cfg.Certs != nil {
		if cfg.Certs.Default != nil {
			termCfg.Default = &terminator.TargetConfig{
				CertFile:    cfg.Certs.Default.Cert,
				KeyFile:     cfg.Certs.Default.Key,
				BackendMTLS: cfg.Certs.Default.BackendMTLS,
			}
		}

		if len(cfg.Certs.Targets) > 0 {
			termCfg.Targets = make(map[string]*terminator.TargetConfig)
			for target, tcfg := range cfg.Certs.Targets {
				termCfg.Targets[target] = &terminator.TargetConfig{
					CertFile:    tcfg.Cert,
					KeyFile:     tcfg.Key,
					BackendMTLS: tcfg.BackendMTLS,
				}
			}
		}
	}

	term, err := terminator.New(termCfg)
	if err != nil {
		return nil, err
	}

	return &TerminatorHandler{term: term}, nil
}

// Name returns the handler name.
func (h *TerminatorHandler) Name() string {
	return "terminator"
}

// OnConnect stores backend mapping by DCID and redirects to internal listener.
func (h *TerminatorHandler) OnConnect(ctx *Context) Result {
	backend := ctx.GetString("backend")
	if backend == "" {
		return Result{Action: Drop, Error: errors.New("no backend")}
	}

	// Extract DCID from InitialPacket
	dcid := terminator.ParseQUICDCID(ctx.InitialPacket)
	if dcid == "" {
		return Result{Action: Drop, Error: errors.New("no DCID in packet")}
	}

	// Store DCID in context for cleanup in OnDisconnect
	ctx.Set("terminator_dcid", dcid)

	// Register backend for this DCID
	h.term.RegisterBackend(dcid, backend)

	sni := ""
	if ctx.Hello != nil {
		sni = ctx.Hello.SNI
	}
	dcidShort := dcid
	if len(dcid) > 8 {
		dcidShort = dcid[:8]
	}
	log.Printf("[terminator] %s (dcid=%s) → %s (via %s)",
		strconv.QuoteToASCII(sni), dcidShort, backend, h.term.InternalAddr)

	// Redirect to internal listener
	ctx.Set("backend", h.term.InternalAddr)
	return Result{Action: Continue}
}

// OnPacket does nothing - ForwarderHandler handles packet forwarding.
func (h *TerminatorHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	return Result{Action: Continue}
}

// OnDisconnect cleans up backend mapping if connection didn't reach terminator.
func (h *TerminatorHandler) OnDisconnect(ctx *Context) {
	// Clean up using DCID stored in context (InitialPacket may be nil at this point)
	dcid := ctx.GetString("terminator_dcid")
	if dcid != "" {
		h.term.UnregisterBackend(dcid)
	}
}

// Shutdown gracefully shuts down the terminator.
func (h *TerminatorHandler) Shutdown(ctx context.Context) error {
	return h.term.Close()
}

// AddPacketHandler registers a handler for decrypted Hytale protocol packets.
// Handlers are executed in the order they are added.
func (h *TerminatorHandler) AddPacketHandler(handler terminator.PacketHandler) {
	h.term.AddPacketHandler(handler)
}
