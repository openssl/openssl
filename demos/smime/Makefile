# Quick instruction:
# To build against an OpenSSL built in the source tree, do this:
#
#    make OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../..
#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./smenc
#    LD_LIBRARY_PATH=../.. ./smdec
#    LD_LIBRARY_PATH=../.. ./smsign
#    LD_LIBRARY_PATH=../.. ./smsign2
#    LD_LIBRARY_PATH=../.. ./smver

# Certificates used in this were copied using the following commands :
# cp ../../test/smime-certs/smrsa1.pem .
# cp ../../test/smime-certs/smrsa2.pem .
# cp ../../test/smime-certs/smroot.pem .

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

all: smdec smenc smsign smsign2 smver

smdec: smdec.o
smenc: smenc.o
smsign: smsign.o
smsign2: smsign2.o
smver: smver.o

smdec smenc smsign smsign2 smver:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) smdec smenc smsign smsign2 smver
	$(RM) smdec.o smenc.o smsign.o smsign2.o smver.o

