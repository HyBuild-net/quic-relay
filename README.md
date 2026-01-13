# HyProxy

[![CI](https://github.com/HyBuild-net/HyProxy/actions/workflows/ci.yml/badge.svg)](https://github.com/HyBuild-net/HyProxy/actions/workflows/ci.yml)

A reverse proxy for Hytale servers. Route players to different backends based on the domain they connect to, enabling multiple servers behind a single IP address.

## Quickstart

**Docker:**
```bash
docker run -p 5520:5520/udp -e HYPROXY_BACKEND=your-server:5520 ghcr.io/hybuild-net/hyproxy
```

**Binary:**
```bash
# Download
curl -LO https://github.com/HyBuild-net/HyProxy/releases/latest/download/hyproxy-linux-amd64
chmod +x hyproxy-linux-amd64

# Run
HYPROXY_BACKEND=your-server:5520 ./hyproxy-linux-amd64 -config '{"handlers":[{"type":"simple-router"},{"type":"forwarder"}]}'
```

For advanced setups with SNI routing or load balancing, see [Handlers](#handlers).

## Build

```bash
make build
```

Produces `bin/proxy`.

## Usage

```bash
# With config file
./bin/proxy -config config.json

# With inline JSON
./bin/proxy -config '{"listen":":5520","handlers":[{"type":"simple-router","config":{"backend":"10.0.0.1:5520"}},{"type":"forwarder"}]}'
```

### Signals

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reload config (only when using a file) |
| `SIGINT` | Shutdown |

## Handlers

Handlers form a chain. Each handler processes the connection and either passes it to the next handler (`Continue`), handles it (`Handled`), or drops it (`Drop`).

### sni-router

Routes connections to different backends based on SNI. Each route can be a single backend or multiple backends (array) for round-robin load balancing. Connections with unknown SNI are dropped.

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5520",
          "lobby.example.com": ["10.0.0.2:5520", "[2001:db8::1]:5520"],
          "minigames.example.com": "myserver.internal.dev:5520"
        }
      }
    },
    {"type": "forwarder"}
  ]
}
```

### simple-router

Routes all connections to one or more backends. Use `backend` for a single destination or `backends` for round-robin load balancing.

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "simple-router",
      "config": {
        "backends": ["10.0.0.1:5520", "10.0.0.2:5520", "[2001:db8::1]:5520"]
      }
    },
    {"type": "forwarder"}
  ]
}
```

### forwarder

Forwards packets to the backend. Must be the last handler in the chain.

### logsni

Logs the SNI of each connection. Useful for debugging.

```json
{
  "listen": ":5520",
  "handlers": [
    {"type": "logsni"},
    {"type": "sni-router", "config": {"routes": {"play.example.com": "10.0.0.1:5520"}}},
    {"type": "forwarder"}
  ]
}
```

## Advanced

Environment variables as fallback when not set in config:
- `HYPROXY_LISTEN` - Listen address (default: `:5520`)
- `HYPROXY_BACKEND` - Backend address for `simple-router`

## License

MIT License. See [LICENSE](LICENSE) for details.
