#
# OpenSSL/fips/hmac/Makefile
#

DIR=	hmac
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
TEST=fips_hmactest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_hmac_selftest.c
LIBOBJ= fips_hmac_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

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

Q=../testvectors/hmac/req
A=../testvectors/hmac/rsp

fips_test:
	-rm -rf $(A)
	mkdir $(A)
	if [ -f $(Q)/HMAC.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_hmactest < $(Q)/HMAC.req > $(A)/HMAC.rsp; fi

lint: lint_common

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean: dclean_common

clean: clean_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_hmac_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_hmac_selftest.o: ../../include/openssl/crypto.h
fips_hmac_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_hmac_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_hmac_selftest.o: ../../include/openssl/hmac.h
fips_hmac_selftest.o: ../../include/openssl/lhash.h
fips_hmac_selftest.o: ../../include/openssl/obj_mac.h
fips_hmac_selftest.o: ../../include/openssl/objects.h
fips_hmac_selftest.o: ../../include/openssl/opensslconf.h
fips_hmac_selftest.o: ../../include/openssl/opensslv.h
fips_hmac_selftest.o: ../../include/openssl/ossl_typ.h
fips_hmac_selftest.o: ../../include/openssl/safestack.h
fips_hmac_selftest.o: ../../include/openssl/stack.h
fips_hmac_selftest.o: ../../include/openssl/symhacks.h ../fips_locl.h
fips_hmac_selftest.o: fips_hmac_selftest.c
fips_hmactest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_hmactest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_hmactest.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_hmactest.o: ../../include/openssl/ec.h ../../include/openssl/err.h
fips_hmactest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_hmactest.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_hmactest.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_hmactest.o: ../../include/openssl/objects.h
fips_hmactest.o: ../../include/openssl/opensslconf.h
fips_hmactest.o: ../../include/openssl/opensslv.h
fips_hmactest.o: ../../include/openssl/ossl_typ.h
fips_hmactest.o: ../../include/openssl/safestack.h
fips_hmactest.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_hmactest.o: ../fips_utl.h fips_hmactest.c
