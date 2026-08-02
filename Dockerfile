# Boardchestrator — multi-stage Docker build
# Stage 1: build Go binary
FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN make build

# Stage 2: runtime (debian-slim has curl for HEALTHCHECK)
FROM debian:bookworm-slim
COPY --from=builder /src/bc /usr/local/bin/bc
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV BC_DB_PATH=/data/bc.db
ENV BC_DATA_DIR=/data
USER nonroot:nonroot
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["curl", "-f", "http://localhost:8080/healthz"]
ENTRYPOINT ["/usr/local/bin/bc", "serve"]
