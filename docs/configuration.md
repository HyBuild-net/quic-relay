# Configuration

## Config file location

| Installation | Path |
|--------------|------|
| Install script | `/etc/quic-relay/config.json` |
| Docker | `/data/config.json` |
| Manual | Pass as first argument: `./proxy config.json` |

## Config structure

```json
{
  "listen": ":5520",
  "session_timeout": 600,
  "handlers": [
    {"type": "handler-name", "config": {...}}
  ]
}
```

## Global options

### listen

Address and port to listen on.

```json
{"listen": ":5520"}
```

Listens on all interfaces, UDP port 5520.

```json
{"listen": "127.0.0.1:5520"}
```

Listens only on localhost.

### session_timeout

Idle timeout in seconds. Sessions without traffic are cleaned up after this duration.

```json
{"session_timeout": 600}
```

Default: `600` (10 minutes)

This value can be changed via hot-reload.

### handlers

Array of handler configurations. See [Handlers](./handlers.md) for details.

## Environment variables

Environment variables are used as fallbacks when not set in the config file:

| Variable | Description | Default |
|----------|-------------|---------|
| `QUIC_RELAY_LISTEN` | Listen address | `:5520` |
| `QUIC_RELAY_BACKEND` | Backend for simple-router | — |

## Hot-reload

Send `SIGHUP` to reload configuration without restarting:

```bash
systemctl reload quic-relay
```

What can be hot-reloaded:
- `session_timeout`
- Handler configurations (routes, limits)

What requires restart:
- `listen` address

## Example configurations

### Single backend

Forward all traffic to one server:

```json
{
  "listen": ":5520",
  "handlers": [
    {"type": "simple-router", "config": {"backend": "10.0.0.1:5520"}},
    {"type": "forwarder"}
  ]
}
```

### Multiple backends with load balancing

Distribute traffic across servers:

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "simple-router",
      "config": {
        "backends": ["10.0.0.1:5520", "10.0.0.2:5520"]
      }
    },
    {"type": "forwarder"}
  ]
}
```

### SNI-based routing with rate limiting

Route by hostname and limit connections:

```json
{
  "listen": ":5520",
  "handlers": [
    {"type": "ratelimit-global", "config": {"max_parallel_connections": 10000}},
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5520",
          "lobby.example.com": ["10.0.0.2:5520", "10.0.0.3:5520"]
        }
      }
    },
    {"type": "forwarder"}
  ]
}
```

### Debug configuration

Log all SNI values:

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
