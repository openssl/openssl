#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./EVP_PKEY_EC_keygen
#    LD_LIBRARY_PATH=../.. ./EVP_PKEY_RSA_keygen
#    LD_LIBRARY_PATH=../.. ./EVP_PKEY_DSA_keygen
#    LD_LIBRARY_PATH=../.. ./EVP_PKEY_DSA_paramgen
#    LD_LIBRARY_PATH=../.. ./EVP_PKEY_DSA_paramvalidate
#    LD_LIBRARY_PATH=../.. ./EVP_PKEY_DSA_paramfromdata

CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=EVP_PKEY_EC_keygen EVP_PKEY_RSA_keygen EVP_PKEY_DSA_keygen \
EVP_PKEY_DSA_paramgen EVP_PKEY_DSA_paramvalidate EVP_PKEY_DSA_paramfromdata

all: $(TESTS)

%.o: %.c dsa.inc
	$(CC) $(CFLAGS) -c $<

EVP_PKEY_EC_keygen: EVP_PKEY_EC_keygen.o

EVP_PKEY_RSA_keygen: EVP_PKEY_RSA_keygen.o

EVP_PKEY_DSA_keygen: EVP_PKEY_DSA_keygen.o

EVP_PKEY_DSA_paramgen: EVP_PKEY_DSA_paramgen.o

EVP_PKEY_DSA_paramvalidate: EVP_PKEY_DSA_paramvalidate.o

EVP_PKEY_DSA_paramfromdata: EVP_PKEY_DSA_paramfromdata.o

clean:
	$(RM) *.o $(TESTS)

.PHONY: test
test: all
	@echo "\nPKEY tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		LD_LIBRARY_PATH=../.. ./$$tst; \
	done
