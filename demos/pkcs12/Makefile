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
# openssl req -x509 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -subj "/C=US/CN=testing.openssl.com" -nodes
# LD_LIBRARY_PATH=../.. ./pkwrite cert.pem password test cert.p12
# LD_LIBRARY_PATH=../.. ./pkread cert.p12 password cert.out
# diff cert.pem cert.out
# Note that cert.out has some extra characters "MAYM\nBHRlc3Q="
# it's a but that needs to be fixed.
#
# LD_LIBRARY_PATH=../.. ./pkwrite key.pem password test key.p12
# LD_LIBRARY_PATH=../.. ./pkread key.p12 password key.out
# diff key.pem key.out
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
