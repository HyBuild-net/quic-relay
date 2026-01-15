# Handlers

Handlers form a processing chain. Each connection passes through handlers sequentially until one handles or drops it.

## Handler chain

A handler can return one of three results:

| Result | Behavior |
|--------|----------|
| `Continue` | Pass connection to next handler |
| `Handled` | Stop processing, connection was handled |
| `Drop` | Terminate the connection |

Example chain:

```json
{
  "handlers": [
    {"type": "logsni"},
    {"type": "ratelimit-global", "config": {"max_parallel_connections": 10000}},
    {"type": "sni-router", "config": {"routes": {"play.example.com": "10.0.0.1:5520"}}},
    {"type": "forwarder"}
  ]
}
```

Processing order:
1. `logsni` logs the SNI and returns `Continue`
2. `ratelimit-global` checks connection count, returns `Continue` or `Drop`
3. `sni-router` sets the backend address and returns `Continue`
4. `forwarder` forwards packets and returns `Handled`

## Built-in handlers

### sni-router

Routes connections based on the SNI hostname.

```json
{
  "type": "sni-router",
  "config": {
    "routes": {
      "play.example.com": "10.0.0.1:5520",
      "lobby.example.com": ["10.0.0.2:5520", "10.0.0.3:5520"]
    }
  }
}
```

**Behavior:**
- Extracts SNI from the QUIC ClientHello
- Looks up the hostname in `routes`
- Single backend: sets that address
- Multiple backends (array): selects one using round-robin
- Unknown SNI: returns `Drop`

### simple-router

Routes all connections to one or more backends. Does not inspect SNI.

```json
{
  "type": "simple-router",
  "config": {
    "backend": "10.0.0.1:5520"
  }
}
```

For load balancing across multiple backends:

```json
{
  "type": "simple-router",
  "config": {
    "backends": ["10.0.0.1:5520", "10.0.0.2:5520", "10.0.0.3:5520"]
  }
}
```

Backends are selected using round-robin.

### ratelimit-global

Limits the total number of concurrent connections.

```json
{
  "type": "ratelimit-global",
  "config": {
    "max_parallel_connections": 10000
  }
}
```

**Behavior:**
- Tracks active connection count
- Returns `Continue` if under limit
- Returns `Drop` if limit reached

### forwarder

Forwards packets between client and backend. This handler should be last in the chain.

```json
{"type": "forwarder"}
```

**Behavior:**
- Reads backend address set by a router handler
- Establishes UDP connection to backend
- Copies packets bidirectionally
- Returns `Handled`

### logsni

Logs the SNI of each connection to stdout.

```json
{"type": "logsni"}
```

Useful for debugging or monitoring which hostnames clients connect to.

### terminator

Terminates QUIC TLS and bridges to backend servers. This allows inspection of raw `hytale/1` protocol traffic. Must be placed before the `forwarder` handler.

::: warning
Requires clients to use the [HytaleCustomCert](https://hybuildnet.github.io/HytaleCustomCert/) plugin to disable certificate binding validation.
:::

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
        "10.0.0.1:5521": {
          "cert": "/etc/quic-relay/backend1.crt",
          "key": "/etc/quic-relay/backend1.key",
          "backend_mtls": true
        }
      }
    },
    "log_client_packets": 5,
    "log_server_packets": 5
  }
}
```

**Config options:**

| Field | Description |
|-------|-------------|
| `listen` | Internal listener address (`auto` for ephemeral port) |
| `certs.default` | Fallback certificate configuration |
| `certs.targets` | Map of backend address → certificate configuration |
| `log_client_packets` | Number of client packets to log (0 = disabled) |
| `log_server_packets` | Number of server packets to log (0 = disabled) |
| `skip_client_packets` | Skip first N client packets before logging |
| `skip_server_packets` | Skip first N server packets before logging |
| `max_packet_size` | Skip packets larger than this (default: 1MB) |

**Certificate config:**

| Field | Description |
|-------|-------------|
| `cert` | Path to TLS certificate |
| `key` | Path to TLS private key |
| `backend_mtls` | Use certificate as client cert for backend mTLS |

**Behavior:**
- Extracts DCID from initial packet and registers backend mapping
- Redirects traffic to internal terminator listener
- Terminates TLS using configured certificate (selected by backend address)
- Bridges all streams bidirectionally to backend
- Returns `Continue` (forwarder still required)

See [hytale-terminating-proxy](https://github.com/HyBuildNet/hytale-terminating-proxy) for standalone library usage.

## Writing custom handlers

Handlers implement the `Handler` interface:

```go
type Handler interface {
    Handle(ctx *ConnContext) Result
}
```

The `ConnContext` contains connection metadata and methods:
- `ctx.SNI()` — extracted Server Name Indication
- `ctx.SetBackend(addr)` — set backend address for forwarder
- `ctx.Drop()` — immediately terminate the session

Return values:
- `Continue` — pass to next handler
- `Handled` — stop chain, connection handled
- `Drop` — terminate connection

Custom handlers require recompiling the project.
