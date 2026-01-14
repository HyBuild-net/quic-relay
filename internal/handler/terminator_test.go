package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "terminator-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Write certificate
	certFile = filepath.Join(tmpDir, "cert.pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create cert file: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	// Write private key
	keyFile = filepath.Join(tmpDir, "key.pem")
	keyOut, err := os.Create(keyFile)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create key file: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()

	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	return certFile, keyFile, cleanup
}

func TestTerminatorHandler_NewAndName(t *testing.T) {
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	cfg := TerminatorConfig{
		Listen: "localhost:0",
		Cert:   certFile,
		Key:    keyFile,
	}

	raw, _ := json.Marshal(cfg)
	h, err := NewTerminatorHandler(raw)
	if err != nil {
		t.Fatalf("NewTerminatorHandler failed: %v", err)
	}

	th := h.(*TerminatorHandler)
	defer th.Shutdown(context.Background())

	if th.Name() != "terminator" {
		t.Errorf("expected name 'terminator', got %q", th.Name())
	}

	if th.internalAddr == "" {
		t.Error("expected internal address to be set")
	}
}

func TestTerminatorHandler_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  TerminatorConfig
		wantErr bool
	}{
		{
			name:    "missing cert",
			config:  TerminatorConfig{Listen: "localhost:0", Key: "nonexistent.key"},
			wantErr: true,
		},
		{
			name:    "missing key",
			config:  TerminatorConfig{Listen: "localhost:0", Cert: "nonexistent.crt"},
			wantErr: true,
		},
		{
			name:    "invalid json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw json.RawMessage
			if tt.config.Cert != "" || tt.config.Key != "" {
				raw, _ = json.Marshal(tt.config)
			} else {
				raw = []byte("{invalid}")
			}

			_, err := NewTerminatorHandler(raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTerminatorHandler() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTerminatorHandler_OnConnect(t *testing.T) {
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	cfg := TerminatorConfig{
		Listen: "localhost:0",
		Cert:   certFile,
		Key:    keyFile,
	}

	raw, _ := json.Marshal(cfg)
	h, err := NewTerminatorHandler(raw)
	if err != nil {
		t.Fatalf("NewTerminatorHandler failed: %v", err)
	}

	th := h.(*TerminatorHandler)
	defer th.Shutdown(context.Background())

	t.Run("valid connection", func(t *testing.T) {
		ctx := &Context{
			Hello: &ClientHello{SNI: "test.example.com"},
		}
		ctx.Set("backend", "backend.example.com:25565")

		result := th.OnConnect(ctx)

		if result.Action != Continue {
			t.Errorf("expected Continue, got %v", result.Action)
		}

		// Check that backend was redirected to internal address
		newBackend := ctx.GetString("backend")
		if newBackend != th.internalAddr {
			t.Errorf("expected backend %q, got %q", th.internalAddr, newBackend)
		}

		// Check that mapping was stored
		entry, ok := th.backends.Load("test.example.com")
		if !ok {
			t.Error("expected backend mapping to be stored")
		}
		be := entry.(*backendEntry)
		if be.addr != "backend.example.com:25565" {
			t.Errorf("expected backend addr 'backend.example.com:25565', got %q", be.addr)
		}
		if be.refCount.Load() != 1 {
			t.Errorf("expected refCount 1, got %d", be.refCount.Load())
		}
	})

	t.Run("missing SNI", func(t *testing.T) {
		ctx := &Context{
			Hello: &ClientHello{SNI: ""},
		}
		ctx.Set("backend", "backend.example.com:25565")

		result := th.OnConnect(ctx)

		if result.Action != Drop {
			t.Errorf("expected Drop, got %v", result.Action)
		}
	})

	t.Run("missing backend", func(t *testing.T) {
		ctx := &Context{
			Hello: &ClientHello{SNI: "test.example.com"},
		}

		result := th.OnConnect(ctx)

		if result.Action != Drop {
			t.Errorf("expected Drop, got %v", result.Action)
		}
	})
}

func TestTerminatorHandler_RefCounting(t *testing.T) {
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	cfg := TerminatorConfig{
		Listen: "localhost:0",
		Cert:   certFile,
		Key:    keyFile,
	}

	raw, _ := json.Marshal(cfg)
	h, err := NewTerminatorHandler(raw)
	if err != nil {
		t.Fatalf("NewTerminatorHandler failed: %v", err)
	}

	th := h.(*TerminatorHandler)
	defer th.Shutdown(context.Background())

	sni := "shared.example.com"
	backend := "backend:25565"

	// Create 3 connections with same SNI
	contexts := make([]*Context, 3)
	for i := 0; i < 3; i++ {
		ctx := &Context{
			Hello: &ClientHello{SNI: sni},
		}
		ctx.Set("backend", backend)
		contexts[i] = ctx

		result := th.OnConnect(ctx)
		if result.Action != Continue {
			t.Fatalf("connection %d: expected Continue, got %v", i, result.Action)
		}
	}

	// Check refCount is 3
	entry, _ := th.backends.Load(sni)
	be := entry.(*backendEntry)
	if be.refCount.Load() != 3 {
		t.Errorf("expected refCount 3, got %d", be.refCount.Load())
	}

	// Disconnect 2 connections
	th.OnDisconnect(contexts[0])
	th.OnDisconnect(contexts[1])

	// Check refCount is 1, entry still exists
	entry, ok := th.backends.Load(sni)
	if !ok {
		t.Fatal("expected entry to still exist")
	}
	be = entry.(*backendEntry)
	if be.refCount.Load() != 1 {
		t.Errorf("expected refCount 1, got %d", be.refCount.Load())
	}

	// Disconnect last connection
	th.OnDisconnect(contexts[2])

	// Check entry is deleted
	_, ok = th.backends.Load(sni)
	if ok {
		t.Error("expected entry to be deleted")
	}
}

func TestTerminatorHandler_OnPacket(t *testing.T) {
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	cfg := TerminatorConfig{
		Listen: "localhost:0",
		Cert:   certFile,
		Key:    keyFile,
	}

	raw, _ := json.Marshal(cfg)
	h, err := NewTerminatorHandler(raw)
	if err != nil {
		t.Fatalf("NewTerminatorHandler failed: %v", err)
	}

	th := h.(*TerminatorHandler)
	defer th.Shutdown(context.Background())

	// OnPacket should always return Continue (does nothing)
	result := th.OnPacket(&Context{}, []byte("test"), Inbound)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v", result.Action)
	}
}

func TestTerminatorHandler_Shutdown(t *testing.T) {
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	cfg := TerminatorConfig{
		Listen: "localhost:0",
		Cert:   certFile,
		Key:    keyFile,
	}

	raw, _ := json.Marshal(cfg)
	h, err := NewTerminatorHandler(raw)
	if err != nil {
		t.Fatalf("NewTerminatorHandler failed: %v", err)
	}

	th := h.(*TerminatorHandler)

	// Shutdown should complete quickly
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = th.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

// TestTerminatorHandler_EndToEnd tests the full flow with a mock backend.
func TestTerminatorHandler_EndToEnd(t *testing.T) {
	// Generate certs for terminator and backend
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	// Start mock backend
	backendListener, err := quic.ListenAddr("localhost:0", generateTLSConfig(t), &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to start backend: %v", err)
	}
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	// Backend echo server - reads and echoes back
	testData := []byte("Hello, QUIC Terminator!")
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := backendListener.Accept(context.Background())
		if err != nil {
			t.Logf("backend accept error: %v", err)
			return
		}

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			t.Logf("backend accept stream error: %v", err)
			conn.CloseWithError(0, "done")
			return
		}

		// Read expected amount
		buf := make([]byte, len(testData))
		n, err := io.ReadFull(stream, buf)
		if err != nil {
			t.Logf("backend read error: %v", err)
			stream.Close()
			conn.CloseWithError(0, "done")
			return
		}

		// Echo back immediately
		_, err = stream.Write(buf[:n])
		if err != nil {
			t.Logf("backend write error: %v", err)
		}

		// Keep connection open until client reads
		time.Sleep(100 * time.Millisecond)
		stream.Close()
		conn.CloseWithError(0, "done")
	}()

	// Create terminator handler
	cfg := TerminatorConfig{
		Listen: "localhost:0",
		Cert:   certFile,
		Key:    keyFile,
	}

	raw, _ := json.Marshal(cfg)
	h, err := NewTerminatorHandler(raw)
	if err != nil {
		t.Fatalf("NewTerminatorHandler failed: %v", err)
	}

	th := h.(*TerminatorHandler)
	defer th.Shutdown(context.Background())

	// Register backend mapping
	ctx := &Context{
		Hello: &ClientHello{SNI: "localhost"},
	}
	ctx.Set("backend", backendAddr)
	th.OnConnect(ctx)

	// Connect client to terminator
	clientConn, err := quic.DialAddr(
		context.Background(),
		th.internalAddr,
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
		&quic.Config{
			MaxIdleTimeout: 30 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer clientConn.CloseWithError(0, "done")

	// Open stream and send data
	stream, err := clientConn.OpenStream()
	if err != nil {
		t.Fatalf("open stream failed: %v", err)
	}
	defer stream.Close()

	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read echo response with timeout
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, len(testData))
	_, err = io.ReadFull(stream, response)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(response) != string(testData) {
		t.Errorf("expected %q, got %q", testData, response)
	}

	// Wait for backend to finish
	<-backendDone
}

// generateTLSConfig creates a TLS config for testing.
func generateTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  privateKey,
		}},
	}
}
