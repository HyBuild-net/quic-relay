FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY pkg/terminator/go.mod pkg/terminator/go.sum ./pkg/terminator/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o quic-relay ./cmd/proxy

FROM alpine:latest
RUN mkdir -p /data
COPY --from=builder /app/quic-relay /usr/local/bin/quic-relay
COPY --from=builder /app/config.json /data/config.json
ENTRYPOINT ["quic-relay"]
CMD ["-config", "/data/config.json"]
