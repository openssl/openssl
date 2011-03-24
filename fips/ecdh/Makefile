#
# OpenSSL/fips/ecdh/Makefile
#

DIR=	ecdh
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
TEST= fips_ecdhvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= 
LIBOBJ= 

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

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_ecdhvs.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_ecdhvs.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_ecdhvs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_ecdhvs.o: ../../include/openssl/ecdh.h ../../include/openssl/err.h
fips_ecdhvs.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_ecdhvs.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_ecdhvs.o: ../../include/openssl/objects.h
fips_ecdhvs.o: ../../include/openssl/opensslconf.h
fips_ecdhvs.o: ../../include/openssl/opensslv.h
fips_ecdhvs.o: ../../include/openssl/ossl_typ.h
fips_ecdhvs.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_ecdhvs.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_ecdhvs.c
