#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./EVP_EC_Signature_demo
#    LD_LIBRARY_PATH=../.. ./EVP_DSA_Signature_demo
#    LD_LIBRARY_PATH=../.. ./EVP_ED_Signature_demo
#    LD_LIBRARY_PATH=../.. ./rsa_pss_direct
#    LD_LIBRARY_PATH=../.. ./rsa_pss_hash

CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=EVP_EC_Signature_demo EVP_DSA_Signature_demo EVP_ED_Signature_demo rsa_pss_direct rsa_pss_hash

all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

EVP_EC_Signature_demo: EVP_EC_Signature_demo.o
EVP_DSA_Signature_demo: EVP_DSA_Signature_demo.o
EVP_ED_Signature_demo: EVP_ED_Signature_demo.o
rsa_pss_direct: rsa_pss_direct.o
rsa_pss_hash: rsa_pss_hash.o

clean:
	$(RM) *.o $(TESTS)

.PHONY: test
test: all
	@echo "\nSignature tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		LD_LIBRARY_PATH=../.. ./$$tst; \
	done
