# Getting Started

## Installation

### Install script (Linux)

```bash
curl -sSL https://raw.githubusercontent.com/HyBuild-net/quic-relay/master/dist/install.sh | sudo bash
sudo systemctl enable --now quic-relay
```

This installs the binary to `/usr/local/bin/quic-relay` and creates a systemd service. Configuration is stored at `/etc/quic-relay/config.json`.

### Docker

```bash
docker run -p 5520:5520/udp ghcr.io/hybuild-net/quic-relay:latest
```

With a custom config:

```bash
docker run -p 5520:5520/udp \
  -v /path/to/config.json:/data/config.json \
  ghcr.io/hybuild-net/quic-relay:latest
```

### Podman

```bash
podman run -p 5520:5520/udp ghcr.io/hybuild-net/quic-relay:latest
```

### Build from source

```bash
git clone https://github.com/HyBuild-net/quic-relay.git
cd quic-relay
make build
```

The binary is written to `bin/proxy`.

## Basic configuration

Create a config file that routes connections based on SNI:

```json
{
  "listen": ":5520",
  "handlers": [
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "10.0.0.1:5520",
          "lobby.example.com": "10.0.0.2:5520"
        }
      }
    },
    {"type": "forwarder"}
  ]
}
```

This configuration:
1. Listens on UDP port 5520
2. Routes `play.example.com` to `10.0.0.1:5520`
3. Routes `lobby.example.com` to `10.0.0.2:5520`
4. Forwards matched connections to their backends

## Reloading configuration

The proxy supports hot-reloading. Send `SIGHUP` to reload the config without dropping existing connections:

```bash
systemctl reload quic-relay
# or
kill -HUP $(pidof quic-relay)
```
