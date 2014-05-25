#
# crypto/ecdsa/Makefile
#

DIR=	ecdsa
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=ecdsatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	ecs_lib.c ecs_asn1.c ecs_ossl.c ecs_sign.c ecs_vrf.c ecs_err.c

LIBOBJ=	ecs_lib.o ecs_asn1.o ecs_ossl.o ecs_sign.o ecs_vrf.o ecs_err.o

SRC= $(LIBSRC)

EXHEADER= ecdsa.h
HEADER=	ecs_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib: lib_arx_common

files: files_common

links: links_up2_common

install: install_common

tags: tags_common

tests:

lint: lint_common

depend: depend_common

dclean: dclean_common

clean: clean_common clean_sub_o_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

ecs_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
ecs_asn1.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
ecs_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ecs_asn1.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ecs_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ecs_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecs_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ecs_asn1.o: ../../include/openssl/symhacks.h ecs_asn1.c ecs_locl.h
ecs_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ecs_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdsa.h
ecs_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ecs_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ecs_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
ecs_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecs_err.o: ecs_err.c
ecs_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ecs_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ecs_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ecs_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
ecs_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ecs_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecs_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ecs_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecs_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ecs_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ecs_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ecs_lib.o: ../../include/openssl/x509_vfy.h ecs_lib.c ecs_locl.h
ecs_ossl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_ossl.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
ecs_ossl.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ecs_ossl.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ecs_ossl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecs_ossl.o: ../../include/openssl/opensslconf.h
ecs_ossl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecs_ossl.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
ecs_ossl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecs_ossl.o: ecs_locl.h ecs_ossl.c
ecs_sign.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_sign.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ecs_sign.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ecs_sign.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ecs_sign.o: ../../include/openssl/engine.h ../../include/openssl/evp.h
ecs_sign.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecs_sign.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ecs_sign.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecs_sign.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
ecs_sign.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ecs_sign.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecs_sign.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ecs_sign.o: ecs_locl.h ecs_sign.c
ecs_vrf.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_vrf.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ecs_vrf.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ecs_vrf.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ecs_vrf.o: ../../include/openssl/engine.h ../../include/openssl/evp.h
ecs_vrf.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecs_vrf.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ecs_vrf.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecs_vrf.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ecs_vrf.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ecs_vrf.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ecs_vrf.o: ../../include/openssl/x509_vfy.h ecs_locl.h ecs_vrf.c
