#
# OpenSSL/crypto/txt_db/Makefile
#

DIR=	txt_db
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
LIBSRC=txt_db.c
LIBOBJ=txt_db.o

SRC= $(LIBSRC)

EXHEADER= txt_db.h
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

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by top Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean: dclean_common

clean: clean_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

txt_db.o: ../../e_os.h ../../include/openssl/bio.h
txt_db.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
txt_db.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
txt_db.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
txt_db.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
txt_db.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
txt_db.o: ../../include/openssl/symhacks.h ../../include/openssl/txt_db.h
txt_db.o: ../cryptlib.h txt_db.c
