# Quick instruction:
# To build against an OpenSSL built in the source tree, do this:
#
#    make OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../..
#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./cms_comp
#    LD_LIBRARY_PATH=../.. ./cms_ddec
#    LD_LIBRARY_PATH=../.. ./cms_dec
#    LD_LIBRARY_PATH=../.. ./cms_denc
#    LD_LIBRARY_PATH=../.. ./cms_enc
#    LD_LIBRARY_PATH=../.. ./cms_sign
#    LD_LIBRARY_PATH=../.. ./cms_sign2
#    LD_LIBRARY_PATH=../.. ./cms_uncomp
#    LD_LIBRARY_PATH=../.. ./cms_ver

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto $(EX_LIBS)

all: cms_comp cms_ddec cms_dec cms_denc cms_enc cms_sign cms_sign2 cms_uncomp cms_ver

cms_comp: cms_comp.o
cms_ddec: cms_ddec.o
cms_dec: cms_dec.o
cms_denc: cms_denc.o
cms_enc: cms_enc.o
cms_sign: cms_sign.o
cms_sign2: cms_sign2.o
cms_uncomp: cms_uncomp.o
cms_ver: cms_ver.o

cms_comp cms_ddec cms_dec cms_denc cms_enc cms_sign cms_sign2 cms_uncomp cms_ver:
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	$(RM) cms_comp cms_ddec cms_dec cms_denc cms_enc cms_sign cms_sign2 cms_uncomp cms_ver *.o
