#
# OpenSSL/fips/utl/Makefile
#

DIR=	utl
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
LIBSRC= fips_err.c fips_md.c fips_enc.c fips_lck.c fips_mem.c
LIBOBJ= fips_err.o fips_md.o fips_enc.o fips_lck.o fips_mem.o

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

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_enc.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_enc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_enc.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_enc.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_enc.o: ../../include/openssl/opensslconf.h
fips_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_enc.o: ../../include/openssl/symhacks.h fips_enc.c
fips_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_err.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_err.o: ../../include/openssl/opensslconf.h
fips_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_err.o: ../../include/openssl/symhacks.h fips_err.c
fips_lck.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_lck.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_lck.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_lck.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_lck.o: ../../include/openssl/opensslconf.h
fips_lck.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_lck.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_lck.o: ../../include/openssl/symhacks.h fips_lck.c
fips_md.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_md.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_md.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_md.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_md.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_md.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
fips_md.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
fips_md.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_md.o: fips_md.c
fips_mem.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_mem.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_mem.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_mem.o: ../../include/openssl/opensslconf.h
fips_mem.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_mem.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_mem.o: ../../include/openssl/symhacks.h fips_mem.c
