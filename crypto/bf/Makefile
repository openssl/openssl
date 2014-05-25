#
# OpenSSL/crypto/blowfish/Makefile
#

DIR=	bf
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

BF_ENC=		bf_enc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=bftest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=bf_skey.c bf_ecb.c bf_enc.c bf_cfb64.c bf_ofb64.c 
LIBOBJ=bf_skey.o bf_ecb.o $(BF_ENC) bf_cfb64.o bf_ofb64.o

SRC= $(LIBSRC)

EXHEADER= blowfish.h
HEADER=	bf_pi.h bf_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib: lib_arx_common

bf-586.s:	asm/bf-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/bf-586.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

files: files_common

links: links_up2_common

# We needed to use force because 'install' matches 'INSTALL' on case
# insensitive systems
# But we renamed 'INSTALL' to 'INSTALL.txt' to make sure that
# install rule looks the same in all directories

install: install_common

tags: tags_common

tests:

lint: lint_common

depend: depend_common

dclean: dclean_common

clean: clean_common clean_s_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

bf_cfb64.o: ../../include/openssl/blowfish.h ../../include/openssl/e_os2.h
bf_cfb64.o: ../../include/openssl/opensslconf.h bf_cfb64.c bf_locl.h
bf_ecb.o: ../../include/openssl/blowfish.h ../../include/openssl/e_os2.h
bf_ecb.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bf_ecb.o: bf_ecb.c bf_locl.h
bf_enc.o: ../../include/openssl/blowfish.h ../../include/openssl/e_os2.h
bf_enc.o: ../../include/openssl/opensslconf.h bf_enc.c bf_locl.h
bf_ofb64.o: ../../include/openssl/blowfish.h ../../include/openssl/e_os2.h
bf_ofb64.o: ../../include/openssl/opensslconf.h bf_locl.h bf_ofb64.c
bf_skey.o: ../../include/openssl/blowfish.h ../../include/openssl/e_os2.h
bf_skey.o: ../../include/openssl/opensslconf.h bf_locl.h bf_pi.h bf_skey.c
