#
# OpenSSL/fips/dh/Makefile
#

DIR=	dh
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
TEST= fips_dhvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_dh_lib.c
LIBOBJ= fips_dh_lib.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

fips_test:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_dh_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_dh_lib.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
fips_dh_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/fips.h
fips_dh_lib.o: ../../include/openssl/opensslconf.h
fips_dh_lib.o: ../../include/openssl/opensslv.h
fips_dh_lib.o: ../../include/openssl/ossl_typ.h
fips_dh_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_dh_lib.o: ../../include/openssl/symhacks.h fips_dh_lib.c
fips_dhvs.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_dhvs.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_dhvs.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
fips_dhvs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_dhvs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_dhvs.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_dhvs.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_dhvs.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_dhvs.o: ../../include/openssl/opensslconf.h
fips_dhvs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_dhvs.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_dhvs.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_dhvs.c
