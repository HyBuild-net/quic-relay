package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"

	"quic-relay/internal/debug"
	"quic-relay/internal/handler"
)

// QUIC Version 1 constants
const (
	quicVersion1 = 0x00000001
)

// PacketType represents the type of a QUIC packet
type PacketType int

const (
	PacketUnknown     PacketType = iota
	PacketInitial                // Long Header, Type 00 - contains ClientHello
	PacketZeroRTT                // Long Header, Type 01
	PacketHandshake              // Long Header, Type 10
	PacketRetry                  // Long Header, Type 11
	PacketShortHeader            // Short Header (1-RTT)
)

// String returns a human-readable name for the packet type
func (t PacketType) String() string {
	switch t {
	case PacketInitial:
		return "Initial"
	case PacketZeroRTT:
		return "0-RTT"
	case PacketHandshake:
		return "Handshake"
	case PacketRetry:
		return "Retry"
	case PacketShortHeader:
		return "1-RTT"
	default:
		return "Unknown"
	}
}

// ClassifyPacket determines the type of a QUIC packet from its first byte
// This is a fast check that doesn't parse the entire packet
func ClassifyPacket(packet []byte) PacketType {
	if len(packet) < 1 {
		return PacketUnknown
	}

	// Check Header Form bit (bit 7)
	// Short Header: Form bit = 0
	// Long Header: Form bit = 1
	if packet[0]&0x80 == 0 {
		return PacketShortHeader
	}

	// Long Header - check Type bits (bits 4-5)
	// The type is encoded in bits 4-5 of the first byte
	longType := (packet[0] & 0x30) >> 4
	switch longType {
	case 0x00:
		return PacketInitial
	case 0x01:
		return PacketZeroRTT
	case 0x02:
		return PacketHandshake
	case 0x03:
		return PacketRetry
	}

	return PacketUnknown
}

// ExtractDCID extracts the Destination Connection ID from any QUIC packet.
// For Long Header packets, DCID length is encoded in the packet.
// For Short Header packets, dcidLen must be provided (from previous Initial).
// Returns (dcid, nil) on success or (nil, error) on failure.
func ExtractDCID(packet []byte, dcidLen int) ([]byte, error) {
	if len(packet) < 1 {
		return nil, errors.New("packet too short")
	}

	// Short Header: DCID starts at byte 1, length must be known
	if packet[0]&0x80 == 0 {
		if dcidLen <= 0 {
			return nil, errors.New("dcidLen required for short header")
		}
		if len(packet) < 1+dcidLen {
			return nil, errors.New("packet too short for DCID")
		}
		return packet[1 : 1+dcidLen], nil
	}

	// Long Header: DCID length is at byte 5
	if len(packet) < 6 {
		return nil, errors.New("packet too short for long header")
	}

	dcidLenFromPacket := int(packet[5])
	if len(packet) < 6+dcidLenFromPacket {
		return nil, errors.New("packet too short for DCID")
	}

	return packet[6 : 6+dcidLenFromPacket], nil
}

// ExtractSCID extracts the Source Connection ID from a Long Header packet.
// Short Header packets don't have SCID - returns error.
// Used to learn server's CID from Initial response for DCID-based routing.
func ExtractSCID(packet []byte) ([]byte, error) {
	if len(packet) < 1 {
		return nil, errors.New("packet too short")
	}

	// Short Header has no SCID
	if packet[0]&0x80 == 0 {
		return nil, errors.New("short header has no SCID")
	}

	// Long Header: Version(4) + DCID_Len(1) + DCID + SCID_Len(1) + SCID
	if len(packet) < 6 {
		return nil, errors.New("packet too short for long header")
	}

	offset := 5 // Skip first byte + version (4 bytes)
	dcidLen := int(packet[offset])
	offset++
	offset += dcidLen

	if offset >= len(packet) {
		return nil, errors.New("packet too short for SCID length")
	}

	scidLen := int(packet[offset])
	offset++

	if offset+scidLen > len(packet) {
		return nil, errors.New("packet too short for SCID")
	}

	return packet[offset : offset+scidLen], nil
}

// ExtractDCIDAndSCID extracts both DCID and SCID from a Long Header packet.
// Returns (dcid, scid, error).
func ExtractDCIDAndSCID(packet []byte) ([]byte, []byte, error) {
	if len(packet) < 1 {
		return nil, nil, errors.New("packet too short")
	}

	// Short Header has no SCID
	if packet[0]&0x80 == 0 {
		return nil, nil, errors.New("short header")
	}

	if len(packet) < 6 {
		return nil, nil, errors.New("packet too short for long header")
	}

	offset := 5 // Skip first byte + version (4 bytes)
	dcidLen := int(packet[offset])
	offset++

	if offset+dcidLen > len(packet) {
		return nil, nil, errors.New("packet too short for DCID")
	}
	dcid := packet[offset : offset+dcidLen]
	offset += dcidLen

	if offset >= len(packet) {
		return nil, nil, errors.New("packet too short for SCID length")
	}

	scidLen := int(packet[offset])
	offset++

	if offset+scidLen > len(packet) {
		return nil, nil, errors.New("packet too short for SCID")
	}
	scid := packet[offset : offset+scidLen]

	return dcid, scid, nil
}

// ExtractAllSCIDs extracts SCIDs from all coalesced packets in a UDP datagram.
// QUIC allows multiple packets to be coalesced in a single datagram.
// The server may use different SCIDs for Initial and Handshake phases.
func ExtractAllSCIDs(datagram []byte) [][]byte {
	var scids [][]byte
	seen := make(map[string]bool)

	offset := 0
	for offset < len(datagram) {
		if offset+1 > len(datagram) {
			break
		}

		// Check if Long Header (first bit = 1)
		if datagram[offset]&0x80 == 0 {
			// Short Header - no more Long Header packets possible
			break
		}

		// Parse Long Header to extract SCID and find packet length
		pkt := datagram[offset:]
		if len(pkt) < 6 {
			break
		}

		// Skip header byte (1) + version (4)
		headerOffset := 5
		dcidLen := int(pkt[headerOffset])
		headerOffset++
		headerOffset += dcidLen

		if headerOffset >= len(pkt) {
			break
		}

		scidLen := int(pkt[headerOffset])
		headerOffset++

		if headerOffset+scidLen > len(pkt) {
			break
		}

		scid := pkt[headerOffset : headerOffset+scidLen]
		scidKey := string(scid)
		if !seen[scidKey] && len(scid) > 0 {
			seen[scidKey] = true
			scidCopy := make([]byte, len(scid))
			copy(scidCopy, scid)
			scids = append(scids, scidCopy)
		}
		headerOffset += scidLen

		// Read variable-length packet length field
		if headerOffset >= len(pkt) {
			break
		}
		pktLen, lenBytes, err := readVarInt(pkt[headerOffset:])
		if err != nil || lenBytes == 0 {
			break
		}
		headerOffset += lenBytes

		// Move to next packet (header + payload length)
		nextOffset := headerOffset + int(pktLen)
		if nextOffset <= 0 || nextOffset > len(pkt) {
			break // Invalid length or end of datagram
		}
		offset += nextOffset
	}

	return scids
}

// PacketTypeError is returned when a packet is not the expected type
type PacketTypeError struct {
	Expected PacketType
	Got      PacketType
}

func (e *PacketTypeError) Error() string {
	return fmt.Sprintf("expected %s packet, got %s", e.Expected, e.Got)
}

// QUIC Initial salt for version 1 (RFC 9001)
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// ExtractCryptoFramesFromPacket decrypts an Initial packet and extracts CRYPTO frames
// This is the main entry point for CRYPTO reassembly
func ExtractCryptoFramesFromPacket(packet []byte) ([]CryptoFrame, error) {
	if len(packet) < 5 {
		return nil, errors.New("packet too short")
	}

	// Verify this is an Initial packet
	pktType := ClassifyPacket(packet)
	if pktType != PacketInitial {
		return nil, &PacketTypeError{Expected: PacketInitial, Got: pktType}
	}

	// Parse version
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != quicVersion1 {
		return nil, fmt.Errorf("unsupported QUIC version: 0x%08x", version)
	}

	offset := 5

	// DCID Length
	if offset >= len(packet) {
		return nil, errors.New("packet too short for DCID length")
	}
	dcidLen := int(packet[offset])
	offset++

	// DCID
	if offset+dcidLen > len(packet) {
		return nil, errors.New("packet too short for DCID")
	}
	dcid := packet[offset : offset+dcidLen]
	offset += dcidLen

	// SCID Length
	if offset >= len(packet) {
		return nil, errors.New("packet too short for SCID length")
	}
	scidLen := int(packet[offset])
	offset++
	offset += scidLen

	// Token Length
	tokenLen, n, err := readVarInt(packet[offset:])
	if err != nil {
		return nil, fmt.Errorf("failed to read token length: %w", err)
	}
	offset += n
	offset += int(tokenLen)

	// Payload Length
	payloadLen, n, err := readVarInt(packet[offset:])
	if err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	offset += n

	if offset+int(payloadLen) > len(packet) {
		return nil, errors.New("packet too short for payload")
	}
	encrypted := packet[offset : offset+int(payloadLen)]

	// Derive keys and decrypt
	clientKey, clientIV, clientHP, err := deriveInitialKeys(dcid)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	decrypted, err := decryptInitialPacket(packet, encrypted, clientKey, clientIV, clientHP)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Extract CRYPTO frames
	return extractCryptoFrames(decrypted), nil
}

// deriveInitialKeys derives the client initial keys from DCID.
func deriveInitialKeys(dcid []byte) (key, iv, hp []byte, err error) {
	// Step 1: Extract initial secret
	// initial_secret = HKDF-Extract(initial_salt, DCID)
	initialSecret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)

	// Step 2: Derive client initial secret
	// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 3: Derive key, iv, hp from client secret
	key, err = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}

	hp, err = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, hp, nil
}

// hkdfExpandLabel implements HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446).
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//
//	HKDF-Expand(Secret, HkdfLabel, Length)
//
// HkdfLabel = struct {
//
//	uint16 length = Length;
//	opaque label<7..255> = "tls13 " + Label;
//	opaque context<0..255> = Context;
//
// };
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// Build HkdfLabel structure
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))

	// uint16 length
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)

	// opaque label<7..255>
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)

	// opaque context<0..255>
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	if len(context) > 0 {
		copy(hkdfLabel[4+len(fullLabel):], context)
	}

	// HKDF-Expand
	h := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}

	return out, nil
}

// decryptInitialPacket removes header protection and decrypts the payload.
func decryptInitialPacket(packet, encrypted, key, iv, hp []byte) ([]byte, error) {
	if len(encrypted) < 20 {
		return nil, errors.New("encrypted payload too short")
	}

	// Create HP cipher
	hpCipher, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}

	// Create AEAD cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	return DecryptWithCachedCrypto(packet, encrypted, hpCipher, aead, iv)
}

// DecryptWithCachedCrypto decrypts an Initial packet using pre-derived keys.
// This is faster than decryptInitialPacket as it reuses cipher objects.
// Uses buffer pool to avoid per-packet allocations.
func DecryptWithCachedCrypto(packet, encrypted []byte,
	hpCipher cipher.Block, aead cipher.AEAD, iv []byte) ([]byte, error) {

	if len(encrypted) < 20 {
		return nil, errors.New("encrypted payload too short")
	}

	// Sample starts at 4 bytes into the payload (after packet number)
	sample := encrypted[4:20]
	var mask [16]byte // Stack allocation
	hpCipher.Encrypt(mask[:], sample)

	// Get buffer from pool for packet copy (avoids allocation)
	bufPtr := handler.GetBuffer()
	defer handler.PutBuffer(bufPtr)
	packetCopy := (*bufPtr)[:len(packet)]
	copy(packetCopy, packet)

	// Remove header protection from first byte
	if packetCopy[0]&0x80 == 0x80 {
		packetCopy[0] ^= mask[0] & 0x0f
	} else {
		packetCopy[0] ^= mask[0] & 0x1f
	}

	// Determine packet number length
	pnLen := (packetCopy[0] & 0x03) + 1

	// Find packet number offset (need to recalculate)
	pnOffset := len(packet) - len(encrypted)

	// Remove header protection from packet number
	for i := 0; i < int(pnLen); i++ {
		packetCopy[pnOffset+i] ^= mask[1+i]
	}

	// Read packet number
	var pn uint64
	for i := 0; i < int(pnLen); i++ {
		pn = (pn << 8) | uint64(packetCopy[pnOffset+i])
	}

	// Create nonce (stack allocation)
	var nonce [12]byte
	copy(nonce[:], iv)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= byte(pn >> (56 - 8*i))
	}

	// Decrypt
	ciphertext := encrypted[pnLen:]
	aad := packetCopy[:pnOffset+int(pnLen)] // Associated data is the header

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// CryptoFrame represents a CRYPTO frame with its offset
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// parseFrames extracts CRYPTO frames from QUIC frames.
// Returns all CRYPTO frames found, sorted by offset.
func parseFrames(data []byte) (*handler.ClientHello, error) {
	frames := extractCryptoFrames(data)

	if len(frames) == 0 {
		return nil, errors.New("no crypto data found")
	}

	// Reassemble CRYPTO data from frames
	cryptoData := reassembleCryptoData(frames)

	if len(cryptoData) == 0 {
		return nil, errors.New("no crypto data after reassembly")
	}

	return parseTLSClientHello(cryptoData)
}

// extractCryptoFrames extracts all CRYPTO frames from decrypted packet data
func extractCryptoFrames(data []byte) []CryptoFrame {
	var frames []CryptoFrame
	offset := 0

	for offset < len(data) {
		frameType, n, err := readVarInt(data[offset:])
		if err != nil {
			break
		}
		offset += n

		switch frameType {
		case 0x00: // PADDING
			// Skip padding bytes
			for offset < len(data) && data[offset] == 0x00 {
				offset++
			}
		case 0x01: // PING
			// No payload
		case 0x02, 0x03: // ACK (RFC 9000 Section 19.3)
			// Largest Acknowledged
			if _, n, err := readVarInt(data[offset:]); err != nil {
				return frames
			} else {
				offset += n
			}
			// ACK Delay
			if _, n, err := readVarInt(data[offset:]); err != nil {
				return frames
			} else {
				offset += n
			}
			// ACK Range Count
			rangeCount, n, err := readVarInt(data[offset:])
			if err != nil {
				return frames
			}
			offset += n
			// First ACK Range
			if _, n, err := readVarInt(data[offset:]); err != nil {
				return frames
			} else {
				offset += n
			}
			// ACK Ranges
			for i := uint64(0); i < rangeCount; i++ {
				// Gap
				if _, n, err := readVarInt(data[offset:]); err != nil {
					return frames
				} else {
					offset += n
				}
				// ACK Range Length
				if _, n, err := readVarInt(data[offset:]); err != nil {
					return frames
				} else {
					offset += n
				}
			}
			// ECN Counts (only for type 0x03)
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					if _, n, err := readVarInt(data[offset:]); err != nil {
						return frames
					} else {
						offset += n
					}
				}
			}
		case 0x06: // CRYPTO
			// Offset (variable-length integer)
			cryptoOffset, n, err := readVarInt(data[offset:])
			if err != nil {
				break
			}
			offset += n

			// Length (variable-length integer)
			length, n, err := readVarInt(data[offset:])
			if err != nil {
				break
			}
			offset += n

			// Crypto data
			if offset+int(length) > len(data) {
				break
			}

			frameData := make([]byte, length)
			copy(frameData, data[offset:offset+int(length)])
			frames = append(frames, CryptoFrame{
				Offset: cryptoOffset,
				Data:   frameData,
			})

			offset += int(length)
		default:
			// Unknown frame type - stop processing to avoid infinite loop
			return frames
		}
	}

	return frames
}

// reassembleCryptoData reassembles CRYPTO frames into a contiguous buffer
func reassembleCryptoData(frames []CryptoFrame) []byte {
	if len(frames) == 0 {
		return nil
	}

	// Find the maximum extent of the data
	var maxEnd uint64
	for _, f := range frames {
		end := f.Offset + uint64(len(f.Data))
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Create buffer and copy data
	// Limit to reasonable size to prevent memory issues
	if maxEnd > 16384 {
		maxEnd = 16384 // Max 16KB for ClientHello
	}

	buffer := make([]byte, maxEnd)
	for _, f := range frames {
		if f.Offset < maxEnd {
			copyLen := uint64(len(f.Data))
			if f.Offset+copyLen > maxEnd {
				copyLen = maxEnd - f.Offset
			}
			copy(buffer[f.Offset:], f.Data[:copyLen])
		}
	}

	return buffer
}

// parseTLSClientHello parses TLS 1.3 ClientHello.
func parseTLSClientHello(data []byte) (*handler.ClientHello, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("TLS record too short: got %d bytes", len(data))
	}

	// Check handshake type (ClientHello = 0x01)
	// Other types: ServerHello=0x02, Certificate=0x0b, etc.
	if data[0] != 0x01 {
		// Provide more context about what we got
		typeStr := fmt.Sprintf("%d (0x%02x)", data[0], data[0])
		if data[0] == 0x00 {
			typeStr = "HelloRequest(0)"
		} else if data[0] == 0x02 {
			typeStr = "ServerHello(2)"
		}
		// Safe slice for logging
		logLen := 6
		if len(data) < logLen {
			logLen = len(data)
		}
		return nil, fmt.Errorf("expected ClientHello(1), got handshake type %s, data[0:%d]=%x", typeStr, logLen, data[0:logLen])
	}

	// Handshake length (3 bytes)
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		return nil, errors.New("ClientHello truncated")
	}

	offset := 4

	// Client Version (2 bytes)
	offset += 2

	// Random (32 bytes)
	offset += 32

	// Session ID Length
	if offset >= len(data) {
		return nil, errors.New("ClientHello too short for session ID")
	}
	sessionIDLen := int(data[offset])
	offset++
	offset += sessionIDLen

	// Cipher Suites Length (2 bytes)
	if offset+2 > len(data) {
		return nil, errors.New("ClientHello too short for cipher suites")
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	offset += cipherSuitesLen

	// Compression Methods Length
	if offset >= len(data) {
		return nil, errors.New("ClientHello too short for compression")
	}
	compressionLen := int(data[offset])
	offset++
	offset += compressionLen

	// Extensions Length (2 bytes)
	if offset+2 > len(data) {
		return nil, errors.New("ClientHello too short for extensions")
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	// Parse extensions
	hello := &handler.ClientHello{
		Raw: data,
	}

	extEnd := offset + extensionsLen
	debug.Printf(" parsing extensions: len=%d, extEnd=%d, dataLen=%d", extensionsLen, extEnd, len(data))
	for offset < extEnd && offset+4 <= len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		extLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		debug.Printf(" extension type=0x%04x len=%d", extType, extLen)

		if offset+extLen > len(data) {
			debug.Printf(" extension truncated: offset=%d extLen=%d dataLen=%d", offset, extLen, len(data))
			break
		}

		switch extType {
		case 0x00: // SNI
			hello.SNI = parseSNI(data[offset : offset+extLen])
			debug.Printf(" parsed SNI=%q", hello.SNI)
		case 0x10: // ALPN
			hello.ALPNProtocols = parseALPN(data[offset : offset+extLen])
			debug.Printf(" parsed ALPN=%v", hello.ALPNProtocols)
		}

		offset += extLen
	}

	return hello, nil
}

// parseSNI extracts the server name from SNI extension.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// List length (2 bytes)
	offset := 2

	// Name type (1 byte, should be 0 for hostname)
	if data[offset] != 0 {
		return ""
	}
	offset++

	// Name length (2 bytes)
	nameLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+nameLen > len(data) {
		return ""
	}

	return string(data[offset : offset+nameLen])
}

// parseALPN extracts protocol names from ALPN extension.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	// List length (2 bytes)
	offset := 2
	var protocols []string

	for offset < len(data) {
		protoLen := int(data[offset])
		offset++
		if offset+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[offset:offset+protoLen]))
		offset += protoLen
	}

	return protocols
}

// readVarInt reads a QUIC variable-length integer.
func readVarInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty data")
	}

	prefix := data[0] >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0, errors.New("data too short for varint")
	}

	var value uint64
	switch length {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(data[0]&0x3f)<<8 | uint64(data[1])
	case 4:
		value = uint64(data[0]&0x3f)<<24 | uint64(data[1])<<16 |
			uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(data[0]&0x3f)<<56 | uint64(data[1])<<48 |
			uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 |
			uint64(data[6])<<8 | uint64(data[7])
	}

	return value, length, nil
}
