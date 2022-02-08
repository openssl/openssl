# Quick instruction:
# To build against an OpenSSL built in the source tree, do this:
#
#    make OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../..
#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./aesccm
#    LD_LIBRARY_PATH=../.. ./aesgcm

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

all: aesccm aesgcm sm4ccm sm4gcm

aesccm: aesccm.o
aesgcm: aesgcm.o
sm4ccm: sm4ccm.o
sm4gcm: sm4gcm.o

aesccm aesgcm sm4ccm sm4gcm:
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	$(RM) aesccm aesgcm sm4ccm sm4gcm *.o
