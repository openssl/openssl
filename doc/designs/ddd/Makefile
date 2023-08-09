#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. make test

TESTS_BASE=ddd-01-conn-blocking ddd-02-conn-nonblocking ddd-02-conn-nonblocking-threads \
		   ddd-03-fd-blocking ddd-04-fd-nonblocking ddd-05-mem-nonblocking ddd-06-mem-uv
TESTS=$(foreach x,$(TESTS_BASE),$(x)-tls $(x)-quic)

CFLAGS = -I../../../include -O3 -g -Wall
LDFLAGS = -L../../..
LDLIBS = -lcrypto -lssl

all: $(TESTS)

clean:
	rm -f $(TESTS) *.o

ddd-06-mem-uv-tls: ddd-06-mem-uv.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" $(LDLIBS) -luv

ddd-06-mem-uv-quic: ddd-06-mem-uv.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DUSE_QUIC -o "$@" "$<" $(LDLIBS) -luv

ddd-%-quic: ddd-%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DUSE_QUIC -o "$@" "$<" $(LDLIBS)

ddd-%-tls: ddd-%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" $(LDLIBS)
