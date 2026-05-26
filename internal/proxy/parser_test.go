package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// Test vectors from RFC 9001 Appendix A and The Illustrated QUIC Connection
func TestDeriveInitialKeys(t *testing.T) {
	// Test vector from https://quic.xargs.org/
	// DCID: 0001020304050607
	// Expected client keys:
	// key: b14b918124fda5c8d79847602fa3520b
	// iv:  ddbc15dea80925a55686a7df
	// hp:  6df4e9d737cdf714711d7c617ee82981

	dcid, _ := hex.DecodeString("0001020304050607")

	key, iv, hp, err := deriveInitialKeys(dcid)
	if err != nil {
		t.Fatalf("deriveInitialKeys failed: %v", err)
	}

	expectedKey, _ := hex.DecodeString("b14b918124fda5c8d79847602fa3520b")
	expectedIV, _ := hex.DecodeString("ddbc15dea80925a55686a7df")
	expectedHP, _ := hex.DecodeString("6df4e9d737cdf714711d7c617ee82981")

	t.Logf("DCID: %x", dcid)
	t.Logf("Derived key: %x", key)
	t.Logf("Expected key: %x", expectedKey)
	t.Logf("Derived IV:  %x", iv)
	t.Logf("Expected IV: %x", expectedIV)
	t.Logf("Derived HP:  %x", hp)
	t.Logf("Expected HP: %x", expectedHP)

	if hex.EncodeToString(key) != hex.EncodeToString(expectedKey) {
		t.Errorf("Key mismatch!\nGot:      %x\nExpected: %x", key, expectedKey)
	}
	if hex.EncodeToString(iv) != hex.EncodeToString(expectedIV) {
		t.Errorf("IV mismatch!\nGot:      %x\nExpected: %x", iv, expectedIV)
	}
	if hex.EncodeToString(hp) != hex.EncodeToString(expectedHP) {
		t.Errorf("HP mismatch!\nGot:      %x\nExpected: %x", hp, expectedHP)
	}
}

// Test the initial secret derivation with RFC 9001 Appendix A test vector
func TestInitialSecret(t *testing.T) {
	// From RFC 9001 Appendix A:
	// DCID: 8394c8f03e515708
	// initial_secret: 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44

	dcid, _ := hex.DecodeString("8394c8f03e515708")

	// HKDF-Extract to get initial_secret
	initialSecret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	expectedInitialSecret, _ := hex.DecodeString("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")

	t.Logf("DCID: %x", dcid)
	t.Logf("Salt: %x", quicV1InitialSalt)
	t.Logf("Initial secret: %x", initialSecret)
	t.Logf("Expected:       %x", expectedInitialSecret)

	if hex.EncodeToString(initialSecret) != hex.EncodeToString(expectedInitialSecret) {
		t.Errorf("Initial secret mismatch!")
	}
}

// Test packet classification
func TestClassifyPacket(t *testing.T) {
	tests := []struct {
		name      string
		firstByte byte
		expected  PacketType
	}{
		{"Initial", 0xC0, PacketInitial},            // 1100 0000 - Long header, type 00
		{"Initial with PN", 0xC3, PacketInitial},    // 1100 0011 - Long header, type 00, PN len 4
		{"0-RTT", 0xD0, PacketZeroRTT},              // 1101 0000 - Long header, type 01
		{"Handshake", 0xE0, PacketHandshake},        // 1110 0000 - Long header, type 10
		{"Retry", 0xF0, PacketRetry},                // 1111 0000 - Long header, type 11
		{"Short Header", 0x40, PacketShortHeader},   // 0100 0000 - Short header
		{"Short Header 2", 0x5F, PacketShortHeader}, // 0101 1111 - Short header
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := []byte{tt.firstByte, 0, 0, 0, 0}
			got := ClassifyPacket(packet)
			if got != tt.expected {
				t.Errorf("ClassifyPacket(%02x) = %v, want %v", tt.firstByte, got, tt.expected)
			}
		})
	}
}

func TestExtractCryptoFramesFromPacket_RejectsOversizedSCID(t *testing.T) {
	packet := []byte{
		0xC0,
		0x00, 0x00, 0x00, 0x01,
		0x00,
		0x20,
	}

	_, err := ExtractCryptoFramesFromPacket(packet)
	if err == nil {
		t.Fatal("expected oversized SCID to return an error")
	}
}

func TestExtractCryptoFramesFromPacket_RejectsOversizedToken(t *testing.T) {
	packet := []byte{
		0xC0,
		0x00, 0x00, 0x00, 0x01,
		0x00,
		0x00,
		0x40, 0x01,
	}

	_, err := ExtractCryptoFramesFromPacket(packet)
	if err == nil {
		t.Fatal("expected oversized token to return an error")
	}
}

func TestParseTLSClientHello_CopiesRawBuffer(t *testing.T) {
	data := make([]byte, 128)
	data[0] = 0x01
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x2b
	data[4] = 0x03
	data[5] = 0x03
	data[38] = 0x00
	data[39] = 0x00
	data[40] = 0x02
	data[41] = 0x13
	data[42] = 0x01
	data[43] = 0x01
	data[44] = 0x00
	data[45] = 0x00
	data[46] = 0x00

	hello, err := parseTLSClientHello(data[:47])
	if err != nil {
		t.Fatalf("parseTLSClientHello failed: %v", err)
	}

	if len(hello.Raw) != 47 {
		t.Fatalf("expected raw length 47, got %d", len(hello.Raw))
	}

	data[0] = 0x02
	if hello.Raw[0] != 0x01 {
		t.Fatal("expected ClientHello.Raw to be a detached copy")
	}
}
