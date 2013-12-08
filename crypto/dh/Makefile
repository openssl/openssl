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
TEST= dhtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= dh_asn1.c dh_gen.c dh_key.c dh_lib.c dh_check.c dh_err.c dh_depr.c \
	dh_ameth.c dh_pmeth.c dh_prn.c
LIBOBJ= dh_asn1.o dh_gen.o dh_key.o dh_lib.o dh_check.o dh_err.o dh_depr.o \
	dh_ameth.o dh_pmeth.o dh_prn.o

SRC= $(LIBSRC)

EXHEADER= dh.h
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

dh_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
dh_ameth.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dh_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_ameth.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
dh_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_ameth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dh_ameth.o: ../asn1/asn1_locl.h ../cryptlib.h dh_ameth.c
dh_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
dh_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dh_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dh_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_asn1.o: ../cryptlib.h dh_asn1.c
dh_check.o: ../../e_os.h ../../include/openssl/bio.h
dh_check.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_check.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_check.o: ../cryptlib.h dh_check.c
dh_depr.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
dh_depr.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
dh_depr.o: ../../include/openssl/stack.h ../cryptlib.h dh_depr.c
dh_err.o: ../../include/openssl/bio.h ../../include/openssl/err.h
dh_err.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
dh_err.o: ../../include/openssl/stack.h dh_err.c
dh_gen.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
dh_gen.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
dh_gen.o: ../../include/openssl/stack.h ../cryptlib.h dh_gen.c
dh_key.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
dh_key.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
dh_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_key.o: ../cryptlib.h dh_key.c
dh_lib.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
dh_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dh_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_lib.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
dh_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dh_lib.o: ../cryptlib.h dh_lib.c
dh_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
dh_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dh_pmeth.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_pmeth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dh_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
dh_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
dh_pmeth.o: ../../include/openssl/x509_vfy.h ../cryptlib.h ../evp/evp_locl.h
dh_pmeth.o: dh_pmeth.c
dh_prn.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
dh_prn.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
dh_prn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_prn.o: ../cryptlib.h dh_prn.c
