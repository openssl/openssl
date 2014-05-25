#
# crypto/seed/Makefile
#

DIR=	seed
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=seed.c seed_ecb.c seed_cbc.c seed_cfb.c seed_ofb.c
LIBOBJ=seed.o seed_ecb.o seed_cbc.o seed_cfb.o seed_ofb.o

SRC= $(LIBSRC)

EXHEADER= seed.h
HEADER= seed_locl.h $(EXHEADER)

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

clean: clean_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

seed.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
seed.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
seed.o: ../../include/openssl/seed.h ../../include/openssl/stack.h
seed.o: ../../include/openssl/symhacks.h seed.c seed_locl.h
seed_cbc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_cbc.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
seed_cbc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_cbc.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_cbc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_cbc.o: seed_cbc.c
seed_cfb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_cfb.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
seed_cfb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_cfb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_cfb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_cfb.o: seed_cfb.c
seed_ecb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_ecb.o: ../../include/openssl/opensslconf.h
seed_ecb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_ecb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_ecb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_ecb.o: seed_ecb.c
seed_ofb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_ofb.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
seed_ofb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_ofb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_ofb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_ofb.o: seed_ofb.c
