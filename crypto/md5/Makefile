#
# OpenSSL/crypto/md5/Makefile
#

DIR=    md5
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

MD5_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=md5test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md5_dgst.c md5_one.c
LIBOBJ=md5_dgst.o md5_one.o $(MD5_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= md5.h
HEADER= md5_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib: lib_arx_common

md5-586.s:	asm/md5-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/md5-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

md5-x86_64.s:	asm/md5-x86_64.pl
	$(PERL) asm/md5-x86_64.pl $(PERLASM_SCHEME) > $@

md5-ia64.s: asm/md5-ia64.S
	$(CC) $(CFLAGS) -E asm/md5-ia64.S | \
	$(PERL) -ne 's/;\s+/;\n/g; print;' > $@

md5-sparcv9.S:	asm/md5-sparcv9.pl
	$(PERL) asm/md5-sparcv9.pl $@ $(CFLAGS)

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

md5_dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/md5.h
md5_dgst.o: ../../include/openssl/opensslconf.h
md5_dgst.o: ../../include/openssl/opensslv.h ../md32_common.h md5_dgst.c
md5_dgst.o: md5_locl.h
md5_one.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md5_one.o: ../../include/openssl/md5.h ../../include/openssl/opensslconf.h
md5_one.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
md5_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
md5_one.o: ../../include/openssl/symhacks.h md5_one.c
