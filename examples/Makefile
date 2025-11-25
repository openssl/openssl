# Makefile for DSMIL OpenSSL Examples
#
# Build examples using DSMIL OpenSSL builds

# Default to DSMIL build, fall back to world build, then system
OPENSSL_PREFIX ?= /opt/openssl-dsmil
ifeq ($(wildcard $(OPENSSL_PREFIX)/include/openssl/ssl.h),)
    OPENSSL_PREFIX := /opt/openssl-world
endif
ifeq ($(wildcard $(OPENSSL_PREFIX)/include/openssl/ssl.h),)
    OPENSSL_PREFIX := /usr
endif

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib
LIBS = -lssl -lcrypto

# Add rpath so examples can find the OpenSSL libraries
LDFLAGS += -Wl,-rpath,$(OPENSSL_PREFIX)/lib64 -Wl,-rpath,$(OPENSSL_PREFIX)/lib

EXAMPLES = dsmil-client dsmil-server check-pqc

all: $(EXAMPLES)

dsmil-client: dsmil-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

dsmil-server: dsmil-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

check-pqc: check-pqc.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean:
	rm -f $(EXAMPLES)

test: all
	@echo "Running example tests..."
	@echo "OpenSSL prefix: $(OPENSSL_PREFIX)"
	@$(OPENSSL_PREFIX)/bin/openssl version
	@echo ""
	@echo "Testing check-pqc..."
	@./check-pqc || true
	@echo ""
	@echo "To test client/server:"
	@echo "  Terminal 1: ./dsmil-server"
	@echo "  Terminal 2: ./dsmil-client localhost 4433"

install:
	@echo "Examples are meant to run from this directory."
	@echo "Copy to desired location if needed."

help:
	@echo "DSMIL OpenSSL Examples Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build all examples (default)"
	@echo "  dsmil-client  - Build TLS client example"
	@echo "  dsmil-server  - Build TLS server example"
	@echo "  check-pqc     - Build PQC feature checker"
	@echo "  clean         - Remove built examples"
	@echo "  test          - Run basic tests"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  OPENSSL_PREFIX - OpenSSL installation prefix"
	@echo "                   (default: /opt/openssl-dsmil)"
	@echo ""
	@echo "Example:"
	@echo "  make OPENSSL_PREFIX=/opt/openssl-world"

.PHONY: all clean test install help
