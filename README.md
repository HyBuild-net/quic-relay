<p align="center">
  <img src="dist/logo.png" alt="QUIC Relay" width="200">
</p>


# QUIC Relay

[![CI](https://github.com/HyBuildNet/quic-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/HyBuildNet/quic-relay/actions/workflows/ci.yml)

A reverse proxy for Hytale servers/Raw QUIC SNI parsing. Route players to different Hytale-Servers based on the domain they connect to.
According to Hytale's official server guide the "Minecraft"-like SRV implementation is not yet available ([source](https://support.hytale.com/hc/en-us/articles/45326769420827-Hytale-Server-Manual#:~:text=ecosystem-,SRV,exists)).
And therefore a QUIC-Proxy might be the only convenient way for achieving standard port + multiple servers.

```mermaid
flowchart LR
    A[Player A] -->|play.example.com| P[QUIC Relay :5520] --> S1[play.example.com]
    B[Player B] -->|lobby.example.com| P --> S2[127.0.0.1:5521]
    C[Player C] -->|minigames.example.com| P --> S3[minigames.dev:67344]
```

## Quickstart

```bash
curl -sSL https://raw.githubusercontent.com/HyBuildNet/quic-relay/master/dist/install.sh | sudo bash
sudo systemctl enable --now quic-relay
```

Configure via `/etc/quic-relay/config.json`. Reload with `systemctl reload quic-relay`.

### Docker

```bash
docker run -p 5520:5520/udp ghcr.io/hybuildnet/quic-relay:latest
```

```bash
podman run -p 5520:5520/udp ghcr.io/hybuildnet/quic-relay:latest
```

Or mount your config:
```bash
docker run -p 5520:5520/udp -v /path/to/config.json:/data/config.json ghcr.io/hybuildnet/quic-relay:latest
```

> **Note:** If your backend servers are on an internal network, ensure the container has network access (e.g., `--network host` or connect to the appropriate Docker network).

## Handlers

Handlers form a chain. Each handler processes the connection and either passes it to the next handler (`Continue`), handles it (`Handled`), or drops it (`Drop`).
Custom handlers can be implemented quite easily, but the project needs to be recompiled.

### SNI Router (Domain-based Routing)

Routes connections based on the domain (SNI) players connect to.

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5520",
          "lobby.example.com": "10.0.0.2:5521",
          "minigames.example.com": "myserver.internal.dev:8000"
        }
      }
    },
    {
      "type": "forwarder"
    }
  ]
}
```

> **Note:** The `forwarder` handler contains the actual forwarding logic. This separation allows replacing it with a [terminating proxy](#tls-termination) for protocol inspection.

### Simple Router

Routes all connections to a single backend.

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "ratelimit-global",
      "config": {
        "max_parallel_connections": 10000
      }
    },
    {
      "type": "simple-router",
      "config": {
        "backend": "10.0.0.1:5527"
      }
    },
    {
      "type": "forwarder"
    }
  ]
}
```

### Rate Limiter

Limits the total number of concurrent connections. New connections are dropped when the limit is reached.

### Forwarder

Forwards packets to the backend. Must be the last handler in the chain.

### Log SNI

Logs the SNI of each connection. Useful for debugging.

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "logsni"
    },
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5521"
        }
      }
    },
    {
      "type": "forwarder"
    }
  ]
}
```

## Advanced

### Load Balancing

Both `sni-router` and `simple-router` support round-robin load balancing. Use an array of backends instead of a single address:

```json
{
  "type": "sni-router",
  "config": {
    "routes": {
      "play.example.com": ["10.0.0.1:5520", "10.0.0.2:5520", "[2001:db8::1]:5520"]
    }
  }
}
```

For `simple-router`, use `backends` (array) instead of `backend` (string).

### TLS Termination

The `terminator` handler terminates QUIC TLS and bridges to backend servers. This allows inspection of raw `hytale/1` protocol traffic. Supports per-target certificates for different backends.

> **Note:** Requires the [HytaleCustomCert](https://hybuildnet.github.io/HytaleCustomCert/) plugin on backend servers with `bypassClientCertificateBinding: true`. This allows the proxy to use the same certificate as the backend server.

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5521",
          "dev.example.com": "10.0.0.2:5522"
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
          },
          "targets": {
            "10.0.0.2:5522": {
              "cert": "/etc/quic-relay/dev.crt",
              "key": "/etc/quic-relay/dev.key"
            }
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

Backend mTLS is enabled by default. Set `"backend_mtls": false` on a target or default to disable.

See [hytale-terminating-proxy](https://github.com/HyBuildNet/hytale-terminating-proxy) for standalone library usage.

### Global Config Options

```json
{
  "listen": ":5520",
  "session_timeout": 600,
  "handlers": [...]
}
```

- `session_timeout` - Idle session timeout in seconds (default: `600` = 10 minutes). Sessions without traffic are cleaned up after this duration. Can be changed via hot-reload (SIGHUP).

### Environment Variables

Fallback when not set in config:
- `QUIC_RELAY_LISTEN` - Listen address (default: `:5520`)
- `QUIC_RELAY_BACKEND` - Backend address for `simple-router`

## Build

```bash
make build
```

Produces `bin/proxy`.

## License

MIT License. See [LICENSE](LICENSE) for details.

*This project is neither related to nor affiliated with HYPIXEL STUDIOS CANADA INC. or any other Trademark owner of Hytale.*
