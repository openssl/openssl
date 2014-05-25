#
# OpenSSL/crypto/rc2/Makefile
#

DIR=	rc2
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=rc2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc2_ecb.c rc2_skey.c rc2_cbc.c rc2cfb64.c rc2ofb64.c
LIBOBJ=rc2_ecb.o rc2_skey.o rc2_cbc.o rc2cfb64.o rc2ofb64.o

SRC= $(LIBSRC)

EXHEADER= rc2.h
HEADER=	rc2_locl.h $(EXHEADER)

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

rc2_cbc.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc2.h
rc2_cbc.o: rc2_cbc.c rc2_locl.h
rc2_ecb.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rc2_ecb.o: ../../include/openssl/rc2.h rc2_ecb.c rc2_locl.h
rc2_skey.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc2.h
rc2_skey.o: rc2_locl.h rc2_skey.c
rc2cfb64.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc2.h
rc2cfb64.o: rc2_locl.h rc2cfb64.c
rc2ofb64.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc2.h
rc2ofb64.o: rc2_locl.h rc2ofb64.c
