#
# crypto/whrlpool/Makefile
#

DIR=	whrlpool
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

WP_ASM_OBJ=wp_block.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=wp_test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=wp_dgst.c wp_block.c
LIBOBJ=wp_dgst.o $(WP_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= whrlpool.h
HEADER= wp_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib: lib_arx_common

wp-mmx.s:	asm/wp-mmx.pl ../perlasm/x86asm.pl
	$(PERL) asm/wp-mmx.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

wp-x86_64.s: asm/wp-x86_64.pl
	$(PERL) asm/wp-x86_64.pl $(PERLASM_SCHEME) > $@

$(LIBOBJ): $(LIBSRC)

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

wp_block.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
wp_block.o: ../../include/openssl/whrlpool.h wp_block.c wp_locl.h
wp_dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
wp_dgst.o: ../../include/openssl/whrlpool.h wp_dgst.c wp_locl.h
