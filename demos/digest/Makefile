#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./EVP_MD_demo

CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=EVP_MD_demo EVP_MD_stdin EVP_MD_xof BIO_f_md

all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

EVP_MD_demo: EVP_MD_demo.o
EVP_MD_stdin: EVP_MD_stdin.o
EVP_MD_xof: EVP_MD_xof.o
BIO_f_md: BIO_f_md.o

.PHONY: test
# Since some of these tests use stdin we use the source file as stdin when running the exes
test: all
	@echo "\nDigest tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		cat $$tst.c | ./$$tst; \
	done

clean:
	$(RM) *.o $(TESTS)
