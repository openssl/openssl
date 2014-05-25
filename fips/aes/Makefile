#
# OpenSSL/fips/aes/Makefile
#

DIR=	aes
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
TEST=fips_aesavs.c fips_gcmtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_aes_selftest.c
LIBOBJ=fips_aes_selftest.o

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
	-find ../testvectors/aes/req -name '*.req' > testlist
	-rm -rf ../testvectors/aes/rsp
	mkdir ../testvectors/aes/rsp
	if [ -s testlist ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_aesavs -d testlist; fi

lint: lint_common

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) \
		$(SRC) $(TEST)

dclean: dclean_common

clean: clean_common
	rm -f asm/*.o testlist

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_aes_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_aes_selftest.o: ../../include/openssl/crypto.h
fips_aes_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_aes_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_aes_selftest.o: ../../include/openssl/lhash.h
fips_aes_selftest.o: ../../include/openssl/obj_mac.h
fips_aes_selftest.o: ../../include/openssl/objects.h
fips_aes_selftest.o: ../../include/openssl/opensslconf.h
fips_aes_selftest.o: ../../include/openssl/opensslv.h
fips_aes_selftest.o: ../../include/openssl/ossl_typ.h
fips_aes_selftest.o: ../../include/openssl/safestack.h
fips_aes_selftest.o: ../../include/openssl/stack.h
fips_aes_selftest.o: ../../include/openssl/symhacks.h ../fips_locl.h
fips_aes_selftest.o: fips_aes_selftest.c
fips_aesavs.o: ../../e_os.h ../../include/openssl/aes.h
fips_aesavs.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_aesavs.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_aesavs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_aesavs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_aesavs.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_aesavs.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_aesavs.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_aesavs.o: ../../include/openssl/opensslconf.h
fips_aesavs.o: ../../include/openssl/opensslv.h
fips_aesavs.o: ../../include/openssl/ossl_typ.h
fips_aesavs.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_aesavs.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_aesavs.c
fips_gcmtest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_gcmtest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_gcmtest.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
fips_gcmtest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_gcmtest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_gcmtest.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_gcmtest.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_gcmtest.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_gcmtest.o: ../../include/openssl/opensslconf.h
fips_gcmtest.o: ../../include/openssl/opensslv.h
fips_gcmtest.o: ../../include/openssl/ossl_typ.h
fips_gcmtest.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_gcmtest.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_gcmtest.c
