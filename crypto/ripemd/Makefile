#
# OpenSSL/crypto/ripemd/Makefile
#

DIR=    ripemd
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

RIP_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=rmdtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rmd_dgst.c rmd_one.c
LIBOBJ=rmd_dgst.o rmd_one.o $(RMD160_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= ripemd.h
HEADER= rmd_locl.h rmdconst.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib: lib_arx_common

rmd-586.s:	asm/rmd-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/rmd-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

files: files_common

links: links_up2_common

install: install_common

tags: tags_common

tests:

lint: lint_common

depend: depend_common

dclean: dclean_common

clean: clean_common clean_s_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

rmd_dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
rmd_dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/ripemd.h
rmd_dgst.o: ../md32_common.h rmd_dgst.c rmd_locl.h rmdconst.h
rmd_one.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rmd_one.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rmd_one.o: ../../include/openssl/ossl_typ.h ../../include/openssl/ripemd.h
rmd_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rmd_one.o: ../../include/openssl/symhacks.h rmd_one.c
