# Quick instruction:
# To build against an OpenSSL built in the source tree, do this:
#
#    make OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../..
#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./smdec
#    LD_LIBRARY_PATH=../.. ./smenc
#    LD_LIBRARY_PATH=../.. ./smsign
#    LD_LIBRARY_PATH=../.. ./smsign2
#    LD_LIBRARY_PATH=../.. ./smver

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto $(EX_LIBS)

all: smdec smenc smsign smsign2 smver

smdec: smdec.o
smenc: smenc.o
smsign: smsign.o
smsign2: smsign2.o
smver: smver.o

smdec smenc smsign smsign2 smver:
        $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
        $(RM) smdec smenc smsign smsign2 smver *.o
