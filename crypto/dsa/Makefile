#
# OpenSSL/crypto/dsa/Makefile
#

DIR=	dsa
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= dsa_gen.c dsa_key.c dsa_lib.c dsa_asn1.c dsa_vrf.c dsa_sign.c \
	dsa_err.c dsa_ossl.c dsa_depr.c dsa_ameth.c dsa_pmeth.c dsa_prn.c
LIBOBJ= dsa_gen.o dsa_key.o dsa_lib.o dsa_asn1.o dsa_vrf.o dsa_sign.o \
	dsa_err.o dsa_ossl.o dsa_depr.o dsa_ameth.o dsa_pmeth.o dsa_prn.o

SRC= $(LIBSRC)

HEADER=	dsa_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

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
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

dsa_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_ameth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_ameth.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
dsa_ameth.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
dsa_ameth.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_ameth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dsa_ameth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dsa_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dsa_ameth.o: ../../include/openssl/objects.h
dsa_ameth.o: ../../include/openssl/opensslconf.h
dsa_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_ameth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
dsa_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dsa_ameth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_ameth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dsa_ameth.o: ../../include/openssl/x509v3.h ../include/internal/asn1_int.h
dsa_ameth.o: ../include/internal/cryptlib.h dsa_ameth.c
dsa_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dsa_asn1.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dsa_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dsa_asn1.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dsa_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_asn1.o: ../../include/openssl/opensslconf.h
dsa_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_asn1.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_asn1.o: ../include/internal/cryptlib.h dsa_asn1.c
dsa_depr.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_depr.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_depr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_depr.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_depr.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_depr.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dsa_depr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_depr.o: ../../include/openssl/opensslconf.h
dsa_depr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_depr.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_depr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dsa_depr.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
dsa_depr.o: dsa_depr.c
dsa_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_err.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dsa_err.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dsa_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dsa_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dsa_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_err.o: dsa_err.c
dsa_gen.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_gen.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_gen.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_gen.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_gen.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_gen.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dsa_gen.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_gen.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dsa_gen.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
dsa_gen.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dsa_gen.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_gen.o: ../include/internal/cryptlib.h dsa_gen.c dsa_locl.h
dsa_key.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_key.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_key.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_key.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_key.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dsa_key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_key.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_key.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_key.o: ../include/internal/cryptlib.h dsa_key.c
dsa_lib.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dsa_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dsa_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dsa_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dsa_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
dsa_lib.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
dsa_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dsa_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_lib.o: ../../include/openssl/ui.h ../../include/openssl/x509.h
dsa_lib.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
dsa_lib.o: dsa_lib.c
dsa_ossl.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_ossl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_ossl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_ossl.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_ossl.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_ossl.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dsa_ossl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_ossl.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_ossl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dsa_ossl.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
dsa_ossl.o: dsa_ossl.c
dsa_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dsa_pmeth.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dsa_pmeth.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dsa_pmeth.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dsa_pmeth.o: ../../include/openssl/ec.h ../../include/openssl/err.h
dsa_pmeth.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dsa_pmeth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_pmeth.o: ../../include/openssl/opensslconf.h
dsa_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
dsa_pmeth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dsa_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_pmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dsa_pmeth.o: ../include/internal/cryptlib.h ../include/internal/evp_int.h
dsa_pmeth.o: dsa_locl.h dsa_pmeth.c
dsa_prn.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_prn.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_prn.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_prn.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_prn.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_prn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dsa_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_prn.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dsa_prn.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dsa_prn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_prn.o: ../include/internal/cryptlib.h dsa_prn.c
dsa_sign.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_sign.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_sign.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_sign.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_sign.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dsa_sign.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_sign.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_sign.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dsa_sign.o: ../include/internal/cryptlib.h dsa_sign.c
dsa_vrf.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dsa_vrf.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dsa_vrf.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dsa_vrf.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dsa_vrf.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dsa_vrf.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dsa_vrf.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dsa_vrf.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
dsa_vrf.o: dsa_vrf.c
