.PHONY: all bpf build test run clean help install

CLANG ?= clang
GO ?= go
BINARY := enclave-xdp
IFACE ?= eth0
ALLOW ?= 127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
METRICS ?= :9090
BPF_SRC := bpf/enclave_xdp.c
BPF_OBJ := bpf/enclave_xdp.o
BPF_HEADERS := bpf/headers

all: bpf build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -O2 -g -Wall -target bpf -I$(BPF_HEADERS) -c $< -o $@

build:
	$(GO) build -v -o $(BINARY) ./cmd/enclave-xdp

test:
	$(GO) test -v ./...

run: build bpf
	sudo ./$(BINARY) -iface $(IFACE) -obj $(BPF_OBJ) -allow "$(ALLOW)" -metrics-addr "$(METRICS)"

install: build bpf
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	install -d /usr/local/lib/enclave-xdp
	install -m 644 $(BPF_OBJ) /usr/local/lib/enclave-xdp/enclave_xdp.o

clean:
	rm -f $(BINARY) $(BPF_OBJ)

help:
	@echo "enclave-xdp build system:"
	@echo "  all     Compile eBPF object and build userspace binary (default)"
	@echo "  bpf     Compile kernel XDP C probe with clang"
	@echo "  build   Build Go userspace CLI"
	@echo "  test    Run Go unit tests"
	@echo "  run     Run enclave-xdp with sudo on IFACE"
	@echo "  install Install binary and BPF object to /usr/local"
	@echo "  clean   Remove build artifacts"
