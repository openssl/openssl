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
TEST=dsatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= dsa_gen.c dsa_key.c dsa_lib.c dsa_asn1.c dsa_vrf.c dsa_sign.c \
	dsa_err.c dsa_ossl.c dsa_depr.c dsa_ameth.c dsa_pmeth.c dsa_prn.c
LIBOBJ= dsa_gen.o dsa_key.o dsa_lib.o dsa_asn1.o dsa_vrf.o dsa_sign.o \
	dsa_err.o dsa_ossl.o dsa_depr.o dsa_ameth.o dsa_pmeth.o dsa_prn.o

SRC= $(LIBSRC)

EXHEADER= dsa.h
HEADER=	dsa_locl.h $(EXHEADER)

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

dsa_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_ameth.o: ../../include/openssl/bio.h ../../include/openssl/cms.h
dsa_ameth.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_ameth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_ameth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dsa_ameth.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
dsa_ameth.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
dsa_ameth.o: dsa_ameth.c
dsa_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dsa_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_asn1.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_asn1.o: ../../include/openssl/stack.h ../cryptlib.h dsa_asn1.c
dsa_depr.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_depr.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_depr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dsa_depr.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
dsa_depr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dsa_depr.o: ../cryptlib.h dsa_depr.c
dsa_err.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_err.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
dsa_err.o: ../../include/openssl/stack.h dsa_err.c
dsa_gen.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_gen.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_gen.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dsa_gen.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
dsa_gen.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dsa_gen.o: ../cryptlib.h dsa_gen.c dsa_locl.h
dsa_key.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_key.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
dsa_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dsa_key.o: ../cryptlib.h dsa_key.c
dsa_lib.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_lib.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
dsa_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dsa_lib.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
dsa_lib.o: ../../include/openssl/x509_vfy.h ../cryptlib.h dsa_lib.c
dsa_ossl.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_ossl.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_ossl.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
dsa_ossl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dsa_ossl.o: ../cryptlib.h dsa_ossl.c
dsa_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dsa_pmeth.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_pmeth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dsa_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dsa_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
dsa_pmeth.o: ../../include/openssl/x509_vfy.h ../cryptlib.h ../evp/evp_locl.h
dsa_pmeth.o: dsa_locl.h dsa_pmeth.c
dsa_prn.o: ../../e_os.h ../../include/openssl/asn1.h
dsa_prn.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dsa_prn.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
dsa_prn.o: ../../include/openssl/stack.h ../cryptlib.h dsa_prn.c
dsa_sign.o: ../../e_os.h ../../include/openssl/bio.h
dsa_sign.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dsa_sign.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
dsa_sign.o: ../../include/openssl/stack.h ../cryptlib.h dsa_sign.c
dsa_vrf.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
dsa_vrf.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
dsa_vrf.o: ../../include/openssl/stack.h ../cryptlib.h dsa_vrf.c
