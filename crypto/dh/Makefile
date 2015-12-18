#
# OpenSSL/crypto/dh/Makefile
#

DIR=	dh
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= dh_asn1.c dh_gen.c dh_key.c dh_lib.c dh_check.c dh_err.c dh_depr.c \
	dh_ameth.c dh_pmeth.c dh_prn.c dh_rfc5114.c dh_kdf.c
LIBOBJ= dh_asn1.o dh_gen.o dh_key.o dh_lib.o dh_check.o dh_err.o dh_depr.o \
	dh_ameth.o dh_pmeth.o dh_prn.o dh_rfc5114.o dh_kdf.o

SRC= $(LIBSRC)

HEADER=	

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

dh_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
dh_ameth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_ameth.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
dh_ameth.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
dh_ameth.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
dh_ameth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dh_ameth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dh_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_ameth.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
dh_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_ameth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
dh_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dh_ameth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_ameth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dh_ameth.o: ../../include/openssl/x509v3.h ../include/internal/asn1_int.h
dh_ameth.o: ../include/internal/cryptlib.h dh_ameth.c
dh_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
dh_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dh_asn1.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dh_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_asn1.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
dh_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_asn1.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
dh_asn1.o: dh_asn1.c
dh_check.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_check.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_check.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_check.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_check.o: ../../include/openssl/opensslconf.h
dh_check.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_check.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_check.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
dh_check.o: dh_check.c
dh_depr.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_depr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_depr.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_depr.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_depr.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dh_depr.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dh_depr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_depr.o: ../include/internal/cryptlib.h dh_depr.c
dh_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_err.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dh_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dh_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_err.o: ../../include/openssl/symhacks.h dh_err.c
dh_gen.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_gen.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_gen.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_gen.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_gen.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dh_gen.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dh_gen.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_gen.o: ../include/internal/cryptlib.h dh_gen.c
dh_kdf.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
dh_kdf.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_kdf.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
dh_kdf.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_kdf.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dh_kdf.o: ../../include/openssl/ec.h ../../include/openssl/evp.h
dh_kdf.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_kdf.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
dh_kdf.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_kdf.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
dh_kdf.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dh_kdf.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_kdf.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dh_kdf.o: ../../include/openssl/x509v3.h dh_kdf.c
dh_key.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_key.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_key.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_key.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_key.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dh_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
dh_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_key.o: ../../include/openssl/symhacks.h ../include/internal/bn_int.h
dh_key.o: ../include/internal/cryptlib.h dh_key.c
dh_lib.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
dh_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_lib.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_lib.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dh_lib.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
dh_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
dh_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
dh_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
dh_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
dh_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
dh_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
dh_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dh_lib.o: ../include/internal/cryptlib.h dh_lib.c
dh_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
dh_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dh_pmeth.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_pmeth.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_pmeth.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dh_pmeth.o: ../../include/openssl/ec.h ../../include/openssl/err.h
dh_pmeth.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dh_pmeth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dh_pmeth.o: ../../include/openssl/opensslconf.h
dh_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
dh_pmeth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dh_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_pmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dh_pmeth.o: ../include/internal/cryptlib.h ../include/internal/evp_int.h
dh_pmeth.o: dh_pmeth.c
dh_prn.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
dh_prn.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_prn.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_prn.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dh_prn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dh_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dh_prn.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dh_prn.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dh_prn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_prn.o: ../include/internal/cryptlib.h dh_prn.c
dh_rfc5114.o: ../../e_os.h ../../include/openssl/bio.h
dh_rfc5114.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_rfc5114.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_rfc5114.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dh_rfc5114.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dh_rfc5114.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_rfc5114.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_rfc5114.o: ../../include/openssl/symhacks.h ../include/internal/bn_dh.h
dh_rfc5114.o: ../include/internal/cryptlib.h dh_rfc5114.c
