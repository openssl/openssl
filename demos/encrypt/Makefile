#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./rsa_encrypt

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=rsa_encrypt

all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

rsa_encrypt: rsa_encrypt.o

clean:
	$(RM) *.o $(TESTS)

.PHONY: test
test: all
	@echo "\nEncrypt tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		LD_LIBRARY_PATH=../.. ./$$tst; \
	done
