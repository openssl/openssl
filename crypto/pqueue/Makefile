#
# OpenSSL/crypto/pqueue/Makefile
#

DIR=	pqueue
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
LIBSRC=pqueue.c
LIBOBJ=pqueue.o

SRC= $(LIBSRC)

EXHEADER= pqueue.h
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

pqueue.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
pqueue.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
pqueue.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
pqueue.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
pqueue.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pqueue.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pqueue.o: ../../include/openssl/symhacks.h ../cryptlib.h pqueue.c pqueue.h
