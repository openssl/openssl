#
# To run the demos when linked with a shared library (default) ensure that
# libcrypto and libssl are on the library path. For example to run the
# tls-client-block demo:
#
#    LD_LIBRARY_PATH=../.. ./tls-client-block

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto -lssl

all: tls-client-block quic-client-block quic-multi-stream tls-client-non-block \
     quic-client-non-block

tls-client-block: tls-client-block.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

quic-client-block: quic-client-block.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

quic-multi-stream: quic-multi-stream.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

tls-client-non-block: tls-client-non-block.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

quic-client-non-block: quic-client-non-block.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) *.o tls-client-block quic-client-block quic-multi-stream \
	      tls-client-non-block quic-client-non-block
