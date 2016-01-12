#
# OpenSSL/crypto/pkcs7/Makefile
#

DIR=	pkcs7
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

PEX_LIBS=
EX_LIBS=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README

LIB=$(TOP)/libcrypto.a
LIBSRC=	pk7_asn1.c pk7_lib.c pkcs7err.c pk7_doit.c pk7_smime.c pk7_attr.c \
	pk7_mime.c bio_pk7.c
LIBOBJ= pk7_asn1.o pk7_lib.o pkcs7err.o pk7_doit.o pk7_smime.o pk7_attr.o \
	pk7_mime.o bio_pk7.o

SRC= $(LIBSRC)

HEADER=	

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff enc dec sign verify

# DO NOT DELETE THIS LINE -- make depend depends on it.

bio_pk7.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bio_pk7.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
bio_pk7.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
bio_pk7.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
bio_pk7.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
bio_pk7.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bio_pk7.o: bio_pk7.c
pk7_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
pk7_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
pk7_asn1.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
pk7_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
pk7_asn1.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
pk7_asn1.o: ../../include/openssl/ec.h ../../include/openssl/err.h
pk7_asn1.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
pk7_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_asn1.o: ../../include/openssl/opensslconf.h
pk7_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk7_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
pk7_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_asn1.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_asn1.o: ../include/internal/cryptlib.h pk7_asn1.c
pk7_attr.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
pk7_attr.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
pk7_attr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
pk7_attr.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk7_attr.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
pk7_attr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_attr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pk7_attr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk7_attr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk7_attr.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
pk7_attr.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
pk7_attr.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_attr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_attr.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_attr.o: pk7_attr.c
pk7_doit.o: ../../e_os.h ../../include/openssl/asn1.h
pk7_doit.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
pk7_doit.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
pk7_doit.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
pk7_doit.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
pk7_doit.o: ../../include/openssl/ec.h ../../include/openssl/err.h
pk7_doit.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
pk7_doit.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_doit.o: ../../include/openssl/opensslconf.h
pk7_doit.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk7_doit.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
pk7_doit.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
pk7_doit.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
pk7_doit.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
pk7_doit.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pk7_doit.o: ../include/internal/cryptlib.h pk7_doit.c
pk7_lib.o: ../../e_os.h ../../include/openssl/asn1.h
pk7_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
pk7_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
pk7_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk7_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
pk7_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pk7_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk7_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk7_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
pk7_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_lib.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
pk7_lib.o: pk7_lib.c
pk7_mime.o: ../../e_os.h ../../include/openssl/asn1.h
pk7_mime.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
pk7_mime.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
pk7_mime.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk7_mime.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
pk7_mime.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_mime.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pk7_mime.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk7_mime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk7_mime.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
pk7_mime.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
pk7_mime.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
pk7_mime.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
pk7_mime.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
pk7_mime.o: pk7_mime.c
pk7_smime.o: ../../e_os.h ../../include/openssl/asn1.h
pk7_smime.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
pk7_smime.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
pk7_smime.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
pk7_smime.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
pk7_smime.o: ../../include/openssl/ec.h ../../include/openssl/err.h
pk7_smime.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
pk7_smime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_smime.o: ../../include/openssl/opensslconf.h
pk7_smime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk7_smime.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
pk7_smime.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_smime.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_smime.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_smime.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
pk7_smime.o: pk7_smime.c
pkcs7err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pkcs7err.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
pkcs7err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
pkcs7err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
pkcs7err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pkcs7err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pkcs7err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pkcs7err.o: pkcs7err.c
