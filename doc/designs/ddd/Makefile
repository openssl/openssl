#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. make test

TESTS=ddd-01-conn-blocking ddd-02-conn-nonblocking ddd-03-fd-blocking ddd-04-fd-nonblocking ddd-05-mem-nonblocking ddd-06-mem-uv

CFLAGS = -I../include -O3 -g -Wall
LDFLAGS = -L..
LDLIBS = -lcrypto -lssl

all: $(TESTS)

clean:
	rm -f $(TESTS) *.o

test: all
	for x in $(TESTS); do echo "$$x"; LD_LIBRARY_PATH="$$(pwd)/.." ./$$x | grep -q '</html>' || { echo >&2 'Error'; exit 1; }; done

ddd-06-mem-uv: ddd-06-mem-uv.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" $(LDLIBS) -luv

ddd-%: ddd-%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" $(LDLIBS)
