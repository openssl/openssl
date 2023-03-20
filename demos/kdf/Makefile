#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./hkdf

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=hkdf pbkdf2 scrypt argon2

all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

hkdf: hkdf.o
pbkdf2: pbkdf2.o
scrypt: scrypt.o
argon2: argon2.o

clean:
	$(RM) *.o $(TESTS)

.PHONY: test
test: all
	@echo "\nKDF tests:"
	@ : 
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst;  \
		./$$tst; \
	done
