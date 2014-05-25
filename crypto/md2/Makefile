#
# OpenSSL/crypto/md/Makefile
#

DIR=	md2
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md2_dgst.c md2_one.c
LIBOBJ=md2_dgst.o md2_one.o

SRC= $(LIBSRC)

EXHEADER= md2.h
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

md2_dgst.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md2_dgst.o: ../../include/openssl/md2.h ../../include/openssl/opensslconf.h
md2_dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
md2_dgst.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
md2_dgst.o: ../../include/openssl/symhacks.h md2_dgst.c
md2_one.o: ../../e_os.h ../../include/openssl/bio.h
md2_one.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
md2_one.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
md2_one.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
md2_one.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
md2_one.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
md2_one.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
md2_one.o: ../cryptlib.h md2_one.c
