#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./tls-client-block

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto -lssl

all: tls-client-block

tls-client-block: tls-client-block.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) *.o tls-client-block
