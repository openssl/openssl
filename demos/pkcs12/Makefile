# Quick instruction:
# To build against an OpenSSL built in the source tree, do this:
#
#    make OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../..
#
# Usage: 
# pkwrite infile password name p12file
# pkread p12file password opfile
#
# To run the demos when linked with a shared library (default):
#
# LD_LIBRARY_PATH=../.. ./pkwrite ../../test/smime-certs/smrsa1.pem "" test cert.p12
# LD_LIBRARY_PATH=../.. ./pkread cert.p12 "" cert.out
# diff ../../test/smime-certs/smrsa1.pem cert.out
#

OPENSSL_INCS_LOCATION=-I../../include 
OPENSSL_LIBS_LOCATION=-L../..
CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

all: pkread pkwrite

pkread: pkread.o
pkwrite: pkwrite.o

pkread pkwrite:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) pkread pkwrite pkread.o pkwrite.o
