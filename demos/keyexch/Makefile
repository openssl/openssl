#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./x25519

CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=x25519

all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%x25519: %x25519.o

.PHONY: test
test: all
	@echo "\nKeyExchange tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		LD_LIBRARY_PATH=../.. ./$$tst; \
	done

clean:
	$(RM) *.o $(TESTS)
