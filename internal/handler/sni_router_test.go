package handler

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestNewDynamicHandler(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "single backend per SNI",
			config:  `{"routes": {"example.com": "backend:443"}}`,
			wantErr: "",
		},
		{
			name:    "multiple backends per SNI",
			config:  `{"routes": {"example.com": ["b1:443", "b2:443"]}}`,
			wantErr: "",
		},
		{
			name:    "mixed single and multiple backends",
			config:  `{"routes": {"a.com": "backend:443", "b.com": ["b1:443", "b2:443"]}}`,
			wantErr: "",
		},
		{
			name:    "empty JSON",
			config:  `{}`,
			wantErr: "requires 'routes' config",
		},
		{
			name:    "missing routes",
			config:  `{"other": "value"}`,
			wantErr: "requires 'routes' config",
		},
		{
			name:    "invalid JSON",
			config:  `{invalid`,
			wantErr: "invalid dynamic config",
		},
		{
			name:    "invalid backend type number",
			config:  `{"routes": {"x.com": 123}}`,
			wantErr: "expected string or array",
		},
		{
			name:    "empty backends array",
			config:  `{"routes": {"x.com": []}}`,
			wantErr: "empty backends",
		},
		{
			name:    "non-string in array",
			config:  `{"routes": {"x.com": ["ok", 123]}}`,
			wantErr: "expected string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewDynamicHandler(json.RawMessage(tt.config))

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h == nil {
				t.Fatal("expected handler, got nil")
			}
		})
	}
}

func TestDynamicHandler_Name(t *testing.T) {
	h, err := NewDynamicHandler(json.RawMessage(`{"routes": {"x.com": "b:443"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Name() != "sni-router" {
		t.Errorf("expected name 'sni-router', got %q", h.Name())
	}
}

func TestDynamicHandler_OnConnect(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		hello       *ClientHello
		wantAction  Action
		wantErr     string
		wantBackend string
	}{
		{
			name:        "successful single backend",
			config:      `{"routes": {"example.com": "backend:443"}}`,
			hello:       &ClientHello{SNI: "example.com"},
			wantAction:  Continue,
			wantBackend: "backend:443",
		},
		{
			name:       "no ClientHello",
			config:     `{"routes": {"example.com": "backend:443"}}`,
			hello:      nil,
			wantAction: Drop,
			wantErr:    "no ClientHello",
		},
		{
			name:       "empty SNI",
			config:     `{"routes": {"example.com": "backend:443"}}`,
			hello:      &ClientHello{SNI: ""},
			wantAction: Drop,
			wantErr:    "no SNI",
		},
		{
			name:       "unknown SNI",
			config:     `{"routes": {"example.com": "backend:443"}}`,
			hello:      &ClientHello{SNI: "unknown.com"},
			wantAction: Drop,
			wantErr:    "unknown SNI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewDynamicHandler(json.RawMessage(tt.config))
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			ctx := &Context{Hello: tt.hello}
			result := h.OnConnect(ctx)

			if result.Action != tt.wantAction {
				t.Errorf("expected action %v, got %v", tt.wantAction, result.Action)
			}

			if tt.wantErr != "" {
				if result.Error == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(result.Error.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, result.Error.Error())
				}
			}

			if tt.wantBackend != "" {
				backend := ctx.GetString("backend")
				if backend != tt.wantBackend {
					t.Errorf("expected backend %q, got %q", tt.wantBackend, backend)
				}
			}
		})
	}
}

func TestDynamicHandler_RoundRobin(t *testing.T) {
	config := `{"routes": {"example.com": ["b1:443", "b2:443"]}}`
	h, err := NewDynamicHandler(json.RawMessage(config))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	counts := make(map[string]int)
	numCalls := 100

	for i := 0; i < numCalls; i++ {
		ctx := &Context{Hello: &ClientHello{SNI: "example.com"}}
		result := h.OnConnect(ctx)
		if result.Action != Continue {
			t.Fatalf("unexpected action: %v", result.Action)
		}
		backend := ctx.GetString("backend")
		counts[backend]++
	}

	// Expect roughly equal distribution
	if counts["b1:443"] != 50 || counts["b2:443"] != 50 {
		t.Errorf("expected 50/50 distribution, got b1=%d, b2=%d", counts["b1:443"], counts["b2:443"])
	}
}

func TestDynamicHandler_OnPacket(t *testing.T) {
	h, err := NewDynamicHandler(json.RawMessage(`{"routes": {"x.com": "b:443"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := &Context{}
	packet := []byte{0x01, 0x02, 0x03}

	result := h.OnPacket(ctx, packet, Inbound)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v", result.Action)
	}

	result = h.OnPacket(ctx, packet, Outbound)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v", result.Action)
	}
}

func TestDynamicHandler_OnDisconnect(t *testing.T) {
	h, err := NewDynamicHandler(json.RawMessage(`{"routes": {"x.com": "b:443"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := &Context{}
	// Should not panic
	h.OnDisconnect(ctx)
}

func TestDynamicHandler_Concurrent(t *testing.T) {
	config := `{"routes": {"a.com": ["b1:443", "b2:443", "b3:443"], "b.com": "single:443"}}`
	h, err := NewDynamicHandler(json.RawMessage(config))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	numCallsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sni := "a.com"
			if id%2 == 0 {
				sni = "b.com"
			}
			for j := 0; j < numCallsPerGoroutine; j++ {
				ctx := &Context{Hello: &ClientHello{SNI: sni}}
				result := h.OnConnect(ctx)
				if result.Action != Continue {
					t.Errorf("unexpected action: %v", result.Action)
				}
				backend := ctx.GetString("backend")
				if backend == "" {
					t.Error("backend not set")
				}
			}
		}(i)
	}

	wg.Wait()
}
