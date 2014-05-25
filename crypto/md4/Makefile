#
# OpenSSL/crypto/md4/Makefile
#

DIR=    md4
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md4test.c
APPS=md4.c

LIB=$(TOP)/libcrypto.a
LIBSRC=md4_dgst.c md4_one.c
LIBOBJ=md4_dgst.o md4_one.o

SRC= $(LIBSRC)

EXHEADER= md4.h
HEADER= md4_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib: lib_arx_common

files: files_common

links: links_up2_common

install: install_common

tags: tags_common

tests:

lint: lint_common

depend: depend_common

dclean: dclean_common
	rm -f ../../include/openssl/$(EXHEADER) ../../test/$(TEST) ../../apps/$(APPS)

clean:
	rm -f asm/mx86unix.cpp *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

md4_dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/md4.h
md4_dgst.o: ../../include/openssl/opensslconf.h
md4_dgst.o: ../../include/openssl/opensslv.h ../md32_common.h md4_dgst.c
md4_dgst.o: md4_locl.h
md4_one.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md4_one.o: ../../include/openssl/md4.h ../../include/openssl/opensslconf.h
md4_one.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
md4_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
md4_one.o: ../../include/openssl/symhacks.h md4_one.c
