#
# To run the demos when linked with a shared library (default) ensure that
# libcrypto and libssl are on the library path. For example:
#
#    LD_LIBRARY_PATH=../.. ./tls-client-block www.example.com 443

TESTS = tls-client-block \
        quic-client-block \
        quic-multi-stream \
        tls-client-non-block \
        quic-client-non-block

CFLAGS  = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS  = -lcrypto -lssl

all: $(TESTS)

tls-client-block: tls-client-block.o
quic-client-block: quic-client-block.o
quic-multi-stream: quic-multi-stream.o
tls-client-non-block: tls-client-non-block.o
quic-client-non-block: quic-client-non-block.o

$(TESTS):
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) $(TESTS) *.o

.PHONY: test
test: all
	@echo "\nTLS and QUIC tests:"
	@echo "skipped"
