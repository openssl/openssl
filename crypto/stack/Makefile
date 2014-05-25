#
# OpenSSL/crypto/stack/Makefile
#

DIR=	stack
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=stack.c
LIBOBJ=stack.o

SRC= $(LIBSRC)

EXHEADER= stack.h safestack.h
HEADER=	$(EXHEADER)

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

stack.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
stack.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
stack.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
stack.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
stack.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
stack.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
stack.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
stack.o: ../../include/openssl/symhacks.h ../cryptlib.h stack.c
