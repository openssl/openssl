#
# OpenSSL/fips/des/Makefile
#

DIR=	des
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

ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_desmovs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_des_selftest.c
LIBOBJ=fips_des_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_common

links: links_top_common

install: install_fips_common

tags: tags_common

tests:

fips_test:
	-find ../testvectors/tdes/req -name '*.req' > testlist
	-rm -rf ../testvectors/tdes/rsp
	mkdir ../testvectors/tdes/rsp
	if [ -s testlist ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_desmovs -d testlist; fi

lint: lint_common

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) \
		$(SRC) $(TEST)
dclean: dclean_common

clean: clean_common
	rm -f asm/*.o testlist

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_des_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_des_selftest.o: ../../include/openssl/crypto.h
fips_des_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_des_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_des_selftest.o: ../../include/openssl/lhash.h
fips_des_selftest.o: ../../include/openssl/obj_mac.h
fips_des_selftest.o: ../../include/openssl/objects.h
fips_des_selftest.o: ../../include/openssl/opensslconf.h
fips_des_selftest.o: ../../include/openssl/opensslv.h
fips_des_selftest.o: ../../include/openssl/ossl_typ.h
fips_des_selftest.o: ../../include/openssl/safestack.h
fips_des_selftest.o: ../../include/openssl/stack.h
fips_des_selftest.o: ../../include/openssl/symhacks.h fips_des_selftest.c
fips_desmovs.o: ../../e_os.h ../../include/openssl/aes.h
fips_desmovs.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_desmovs.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_desmovs.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
fips_desmovs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_desmovs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_desmovs.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_desmovs.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_desmovs.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_desmovs.o: ../../include/openssl/opensslconf.h
fips_desmovs.o: ../../include/openssl/opensslv.h
fips_desmovs.o: ../../include/openssl/ossl_typ.h
fips_desmovs.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_desmovs.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_desmovs.o: ../../include/openssl/ui_compat.h ../fips_utl.h fips_desmovs.c
