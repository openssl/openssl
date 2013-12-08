#
# OpenSSL/crypto/rsa/Makefile
#

DIR=	rsa
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=rsa_test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= rsa_eay.c rsa_gen.c rsa_lib.c rsa_sign.c rsa_saos.c rsa_err.c \
	rsa_pk1.c rsa_ssl.c rsa_none.c rsa_oaep.c rsa_chk.c rsa_null.c \
	rsa_pss.c rsa_x931.c rsa_asn1.c rsa_depr.c rsa_ameth.c rsa_prn.c \
	rsa_pmeth.c rsa_crpt.c
LIBOBJ= rsa_eay.o rsa_gen.o rsa_lib.o rsa_sign.o rsa_saos.o rsa_err.o \
	rsa_pk1.o rsa_ssl.o rsa_none.o rsa_oaep.o rsa_chk.o rsa_null.o \
	rsa_pss.o rsa_x931.o rsa_asn1.o rsa_depr.o rsa_ameth.o rsa_prn.o \
	rsa_pmeth.o rsa_crpt.o

SRC= $(LIBSRC)

EXHEADER= rsa.h
HEADER=	$(EXHEADER)

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

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

rsa_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_ameth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
rsa_ameth.o: ../../include/openssl/cms.h ../../include/openssl/err.h
rsa_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_ameth.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
rsa_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_ameth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rsa_ameth.o: ../asn1/asn1_locl.h ../cryptlib.h rsa_ameth.c
rsa_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
rsa_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rsa_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
rsa_asn1.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
rsa_asn1.o: ../../include/openssl/x509_vfy.h ../cryptlib.h rsa_asn1.c
rsa_chk.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rsa_chk.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_chk.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_chk.o: rsa_chk.c
rsa_crpt.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_crpt.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
rsa_crpt.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_crpt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rsa_crpt.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
rsa_crpt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_crpt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rsa_crpt.o: ../cryptlib.h rsa_crpt.c
rsa_depr.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_depr.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_depr.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
rsa_depr.o: ../../include/openssl/stack.h ../cryptlib.h rsa_depr.c
rsa_eay.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_eay.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_eay.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
rsa_eay.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_eay.o: ../cryptlib.h rsa_eay.c
rsa_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rsa_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_err.o: rsa_err.c
rsa_gen.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_gen.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_gen.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
rsa_gen.o: ../../include/openssl/stack.h ../cryptlib.h rsa_gen.c
rsa_lib.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_lib.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
rsa_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rsa_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
rsa_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rsa_lib.o: ../cryptlib.h rsa_lib.c
rsa_none.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_none.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_none.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
rsa_none.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_none.o: ../cryptlib.h rsa_none.c
rsa_null.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_null.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_null.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
rsa_null.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_null.o: ../cryptlib.h rsa_null.c
rsa_oaep.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_oaep.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_oaep.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_oaep.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rsa_oaep.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_oaep.o: ../cryptlib.h rsa_oaep.c
rsa_pk1.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_pk1.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_pk1.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
rsa_pk1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_pk1.o: ../cryptlib.h rsa_pk1.c
rsa_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
rsa_pmeth.o: ../../include/openssl/cms.h ../../include/openssl/err.h
rsa_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_pmeth.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
rsa_pmeth.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_pmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rsa_pmeth.o: ../cryptlib.h ../evp/evp_locl.h rsa_locl.h rsa_pmeth.c
rsa_prn.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_prn.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_prn.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
rsa_prn.o: ../../include/openssl/stack.h ../cryptlib.h rsa_prn.c
rsa_pss.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_pss.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_pss.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_pss.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rsa_pss.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_pss.o: ../cryptlib.h rsa_pss.c
rsa_saos.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_saos.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_saos.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_saos.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
rsa_saos.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_saos.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rsa_saos.o: ../cryptlib.h rsa_saos.c
rsa_sign.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_sign.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_sign.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_sign.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
rsa_sign.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_sign.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rsa_sign.o: ../cryptlib.h rsa_locl.h rsa_sign.c
rsa_ssl.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_ssl.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_ssl.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
rsa_ssl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_ssl.o: ../cryptlib.h rsa_ssl.c
rsa_x931.o: ../../e_os.h ../../include/openssl/asn1.h
rsa_x931.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rsa_x931.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rsa_x931.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rsa_x931.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_x931.o: ../cryptlib.h rsa_x931.c
