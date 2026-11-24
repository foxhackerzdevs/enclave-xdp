# Build stage
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    gcc-multilib \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN make all

# Final minimal runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/enclave-xdp /app/enclave-xdp
COPY --from=builder /build/bpf/enclave_xdp.o /app/bpf/enclave_xdp.o

EXPOSE 9090

ENTRYPOINT ["/app/enclave-xdp"]
CMD ["-iface=eth0", "-obj=/app/bpf/enclave_xdp.o", "-metrics-addr=:9090"]
