# QUIC Relay

QUIC Relay is a reverse proxy for routing QUIC connections based on SNI (Server Name Indication). It was built for Hytale servers but works with any QUIC-based protocol.

## What it does

The proxy inspects the SNI field in incoming QUIC handshakes and routes connections to different backends based on the hostname. This allows multiple servers to share a single public IP and port.

```
┌──────────────┐                        ┌─────────────────────┐
│   Client A   │──play.example.com────▶│                     │──▶ Backend 1
├──────────────┤                        │     QUIC Relay      │
│   Client B   │──lobby.example.com───▶│     (port 5520)     │──▶ Backend 2
├──────────────┤                        │                     │
│   Client C   │──other.example.com───▶│                     │──▶ Backend 3
└──────────────┘                        └─────────────────────┘
```

## Why this exists

Hytale uses QUIC on UDP port 5520. Unlike TCP-based games, there's no established method (like SRV records for Minecraft) to redirect players to different ports. Running multiple servers on one IP currently requires either:

- Different ports per server (inconvenient for players)
- A reverse proxy that routes based on SNI (this project)

## Architecture

The proxy uses a handler chain. Each handler processes connections sequentially and decides whether to:

- **Continue** — pass to the next handler
- **Handled** — stop processing, connection was handled
- **Drop** — terminate the connection

This design allows combining handlers for different purposes: logging, rate limiting, routing, and forwarding.