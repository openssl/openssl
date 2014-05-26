#
# OpenSSL/crypto/dso/Makefile
#

DIR=	dso
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= dso_dl.c dso_dlfcn.c dso_err.c dso_lib.c dso_null.c \
	dso_openssl.c dso_win32.c dso_vms.c dso_beos.c
LIBOBJ= dso_dl.o dso_dlfcn.o dso_err.o dso_lib.o dso_null.o \
	dso_openssl.o dso_win32.o dso_vms.o dso_beos.o

SRC= $(LIBSRC)

EXHEADER= dso.h
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

clean: clean_common clean_sub_o_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

dso_beos.o: ../../e_os.h ../../include/openssl/bio.h
dso_beos.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_beos.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_beos.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_beos.o: ../../include/openssl/opensslconf.h
dso_beos.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dso_beos.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_beos.o: ../../include/openssl/symhacks.h ../cryptlib.h dso_beos.c
dso_dl.o: ../../e_os.h ../../include/openssl/bio.h
dso_dl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_dl.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_dl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_dl.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_dl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dso_dl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_dl.o: ../cryptlib.h dso_dl.c
dso_dlfcn.o: ../../e_os.h ../../include/openssl/bio.h
dso_dlfcn.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_dlfcn.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_dlfcn.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_dlfcn.o: ../../include/openssl/opensslconf.h
dso_dlfcn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dso_dlfcn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_dlfcn.o: ../../include/openssl/symhacks.h ../cryptlib.h dso_dlfcn.c
dso_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
dso_err.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dso_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_err.o: dso_err.c
dso_lib.o: ../../e_os.h ../../include/openssl/bio.h
dso_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_lib.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dso_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_lib.o: ../cryptlib.h dso_lib.c
dso_null.o: ../../e_os.h ../../include/openssl/bio.h
dso_null.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_null.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_null.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_null.o: ../../include/openssl/opensslconf.h
dso_null.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dso_null.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_null.o: ../../include/openssl/symhacks.h ../cryptlib.h dso_null.c
dso_openssl.o: ../../e_os.h ../../include/openssl/bio.h
dso_openssl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_openssl.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_openssl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_openssl.o: ../../include/openssl/opensslconf.h
dso_openssl.o: ../../include/openssl/opensslv.h
dso_openssl.o: ../../include/openssl/ossl_typ.h
dso_openssl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_openssl.o: ../../include/openssl/symhacks.h ../cryptlib.h dso_openssl.c
dso_vms.o: ../../e_os.h ../../include/openssl/bio.h
dso_vms.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_vms.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_vms.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_vms.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_vms.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dso_vms.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_vms.o: ../cryptlib.h dso_vms.c
dso_win32.o: ../../e_os.h ../../include/openssl/bio.h
dso_win32.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dso_win32.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
dso_win32.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_win32.o: ../../include/openssl/opensslconf.h
dso_win32.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dso_win32.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_win32.o: ../../include/openssl/symhacks.h ../cryptlib.h dso_win32.c
