#
# SSLeay/fips/rand/Makefile
#

DIR=	rand
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
TEST= fips_randtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_rand.c
LIBOBJ=fips_rand.o

SRC= $(LIBSRC)

EXHEADER= fips_rand.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips SDIRS=$(DIR) sub_all)

all:	check lib

check:
	TOP=`pwd`/$(TOP) ../fips_check_sha1 fingerprint.sha1 $(SRC) $(HEADER)

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@sleep 2; touch lib

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

fips_rand.o: ../../e_os.h ../../include/openssl/bio.h
fips_rand.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_rand.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
fips_rand.o: ../../include/openssl/err.h ../../include/openssl/fips_rand.h
fips_rand.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
fips_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_rand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
fips_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rand.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
fips_rand.o: fips_rand.c
fips_randtest.o: ../../e_os.h ../../include/openssl/bio.h
fips_randtest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_randtest.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
fips_randtest.o: ../../include/openssl/err.h ../../include/openssl/fips_rand.h
fips_randtest.o: ../../include/openssl/lhash.h
fips_randtest.o: ../../include/openssl/opensslconf.h
fips_randtest.o: ../../include/openssl/opensslv.h
fips_randtest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_randtest.o: ../../include/openssl/safestack.h
fips_randtest.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_randtest.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
fips_randtest.o: fips_randtest.c
