# TLS Termination

The `terminator` handler terminates QUIC TLS and bridges to backend servers. This allows inspection of raw `hytale/1` protocol traffic.

## Requirements

Requires the [HytaleCustomCert](https://hybuildnet.github.io/HytaleCustomCert/) plugin on backend servers with `bypassClientCertificateBinding: true`. This allows the proxy to use the same certificate as the backend server.

## Basic usage

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5521"
        }
      }
    },
    {
      "type": "terminator",
      "config": {
        "listen": "auto",
        "certs": {
          "default": {
            "cert": "/etc/quic-relay/server.crt",
            "key": "/etc/quic-relay/server.key"
          }
        }
      }
    },
    {
      "type": "forwarder"
    }
  ]
}
```

## Per-target certificates

Different backends can use different certificates:

```json
{
  "type": "terminator",
  "config": {
    "listen": "auto",
    "certs": {
      "default": {
        "cert": "/etc/quic-relay/server.crt",
        "key": "/etc/quic-relay/server.key"
      },
      "targets": {
        "10.0.0.2:5522": {
          "cert": "/etc/quic-relay/dev.crt",
          "key": "/etc/quic-relay/dev.key"
        }
      }
    }
  }
}
```

## Config options

| Field | Description |
|-------|-------------|
| `listen` | Internal listener address (`auto` for ephemeral port) |
| `certs.default` | Fallback certificate |
| `certs.targets` | Backend address to certificate mapping |

### Certificate config

| Field | Description |
|-------|-------------|
| `cert` | Path to TLS certificate |
| `key` | Path to TLS private key |
| `backend_mtls` | Use certificate for backend mTLS (default: `true`) |

### Debug mode

Enable protocol-level packet logging:

| Field | Description |
|-------|-------------|
| `debug` | Enable packet parsing and logging (`true`/`false`) |
| `debug_packet_limit` | Max packets to log per stream (0 = unlimited) |

Example:

```json
{
  "type": "terminator",
  "config": {
    "listen": "auto",
    "certs": {
      "default": {
        "cert": "server.crt",
        "key": "server.key"
      }
    },
    "debug": true,
    "debug_packet_limit": 100
  }
}
```

When enabled, logs Hytale protocol packets:

```
[packet] (C->S) Connect (0x00000001) 128 bytes
[packet] (C->S)   user=PlayerName uuid=12345678-...
[packet] (S->C) 0x00000002 64 bytes
```

## Packet handlers (programmatic)

For advanced use cases, packet handlers can be registered programmatically to inspect, filter, or modify decrypted packets:

```go
termHandler := findTerminatorHandler(chain)

termHandler.AddPacketHandler(func(dcid string, pkt *protohytale.Packet, fromClient bool) ([]byte, terminator.PacketAction) {
    // Log all packets
    log.Printf("[%s] 0x%08X %d bytes", dcid[:8], pkt.ID, len(pkt.Data))

    // Drop specific packets
    if pkt.ID == 0xDEADBEEF {
        return nil, terminator.PacketDrop
    }

    // Modify packet data
    if pkt.ID == 0x1234 {
        modified := transform(pkt.Data)
        return modified, terminator.PacketContinue
    }

    // Pass through unchanged
    return nil, terminator.PacketContinue
})
```

Handlers are executed in order of registration. Each handler can:
- **Inspect** packets (logging, metrics)
- **Drop** packets (filtering)
- **Modify** packet data (transformation)

## Standalone library

The terminator is available as a standalone Go library in `pkg/terminator`.
