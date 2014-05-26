#
# OpenSSL/fips/ecdsa/Makefile
#

DIR=	ecdsa
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
TEST= fips_ecdsavs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_ecdsa_lib.c fips_ecdsa_sign.c fips_ecdsa_selftest.c
LIBOBJ= fips_ecdsa_lib.o fips_ecdsa_sign.o fips_ecdsa_selftest.o

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

fips_test:

lint: lint_common

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean: dclean_common

clean: clean_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_ecdsa_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_ecdsa_lib.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_ecdsa_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_ecdsa_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/fips.h
fips_ecdsa_lib.o: ../../include/openssl/opensslconf.h
fips_ecdsa_lib.o: ../../include/openssl/opensslv.h
fips_ecdsa_lib.o: ../../include/openssl/ossl_typ.h
fips_ecdsa_lib.o: ../../include/openssl/safestack.h
fips_ecdsa_lib.o: ../../include/openssl/stack.h
fips_ecdsa_lib.o: ../../include/openssl/symhacks.h fips_ecdsa_lib.c
fips_ecdsa_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_ecdsa_selftest.o: ../../include/openssl/bn.h
fips_ecdsa_selftest.o: ../../include/openssl/crypto.h
fips_ecdsa_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_ecdsa_selftest.o: ../../include/openssl/ecdsa.h
fips_ecdsa_selftest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_ecdsa_selftest.o: ../../include/openssl/fips.h
fips_ecdsa_selftest.o: ../../include/openssl/lhash.h
fips_ecdsa_selftest.o: ../../include/openssl/obj_mac.h
fips_ecdsa_selftest.o: ../../include/openssl/objects.h
fips_ecdsa_selftest.o: ../../include/openssl/opensslconf.h
fips_ecdsa_selftest.o: ../../include/openssl/opensslv.h
fips_ecdsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_ecdsa_selftest.o: ../../include/openssl/safestack.h
fips_ecdsa_selftest.o: ../../include/openssl/stack.h
fips_ecdsa_selftest.o: ../../include/openssl/symhacks.h fips_ecdsa_selftest.c
fips_ecdsa_sign.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_ecdsa_sign.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_ecdsa_sign.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_ecdsa_sign.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
fips_ecdsa_sign.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
fips_ecdsa_sign.o: ../../include/openssl/obj_mac.h
fips_ecdsa_sign.o: ../../include/openssl/objects.h
fips_ecdsa_sign.o: ../../include/openssl/opensslconf.h
fips_ecdsa_sign.o: ../../include/openssl/opensslv.h
fips_ecdsa_sign.o: ../../include/openssl/ossl_typ.h
fips_ecdsa_sign.o: ../../include/openssl/safestack.h
fips_ecdsa_sign.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_ecdsa_sign.o: ../../include/openssl/symhacks.h fips_ecdsa_sign.c
fips_ecdsavs.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_ecdsavs.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_ecdsavs.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_ecdsavs.o: ../../include/openssl/ec.h ../../include/openssl/ecdsa.h
fips_ecdsavs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_ecdsavs.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_ecdsavs.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_ecdsavs.o: ../../include/openssl/objects.h
fips_ecdsavs.o: ../../include/openssl/opensslconf.h
fips_ecdsavs.o: ../../include/openssl/opensslv.h
fips_ecdsavs.o: ../../include/openssl/ossl_typ.h
fips_ecdsavs.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_ecdsavs.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_ecdsavs.c
