#
# SSLeay/fips/rsa/Makefile
#

DIR=	rsa
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_rsa_eay.c fips_rsa_gen.c fips_rsa_selftest.c
LIBOBJ=fips_rsa_eay.o fips_rsa_gen.o fips_rsa_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all:	check lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@sleep 2; touch lib

check:
	TOP=`pwd`/$(TOP) ../fips_check_sha1 fingerprint.sha1 $(SRC) $(HEADER)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_rsa_eay.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_eay.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_eay.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_eay.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_rsa_eay.o: ../../include/openssl/opensslconf.h
fips_rsa_eay.o: ../../include/openssl/opensslv.h
fips_rsa_eay.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_rsa_eay.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_rsa_eay.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rsa_eay.o: fips_rsa_eay.c
fips_rsa_gen.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_gen.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_gen.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_gen.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_rsa_gen.o: ../../include/openssl/opensslconf.h
fips_rsa_gen.o: ../../include/openssl/opensslv.h
fips_rsa_gen.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rsa.h
fips_rsa_gen.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_rsa_gen.o: ../../include/openssl/symhacks.h fips_rsa_gen.c
fips_rsa_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_selftest.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_selftest.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_rsa_selftest.o: ../../include/openssl/opensslconf.h
fips_rsa_selftest.o: ../../include/openssl/opensslv.h
fips_rsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_rsa_selftest.o: ../../include/openssl/rsa.h
fips_rsa_selftest.o: ../../include/openssl/safestack.h
fips_rsa_selftest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_rsa_selftest.o: ../../include/openssl/symhacks.h fips_rsa_selftest.c
