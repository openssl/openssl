# Quick instruction:
# To build against an Opentls built in the source tree, do this:
#
#    make OPENtls_INCS_LOCATION=-I../../include OPENtls_LIBS_LOCATION=-L../..
#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./aesccm
#    LD_LIBRARY_PATH=../.. ./aesgcm

CFLAGS = $(OPENtls_INCS_LOCATION)
LDFLAGS = $(OPENtls_LIBS_LOCATION) -ltls -lcrypto

all: aesccm aesgcm

aesccm: aesccm.o
aesgcm: aesgcm.o

aesccm aesgcm:
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	$(RM) aesccm aesgcm *.o
