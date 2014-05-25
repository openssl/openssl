#
# OpenSSL/crypto/rc5/Makefile
#

DIR=	rc5
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

RC5_ENC=		rc5_enc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=rc5test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc5_skey.c rc5_ecb.c rc5_enc.c rc5cfb64.c rc5ofb64.c 
LIBOBJ=rc5_skey.o rc5_ecb.o $(RC5_ENC) rc5cfb64.o rc5ofb64.o

SRC= $(LIBSRC)

EXHEADER= rc5.h
HEADER=	rc5_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib: lib_arx_common

rc5-586.s: asm/rc5-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/rc5-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

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

rc5_ecb.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rc5_ecb.o: ../../include/openssl/rc5.h rc5_ecb.c rc5_locl.h
rc5_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc5.h
rc5_enc.o: rc5_enc.c rc5_locl.h
rc5_skey.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc5.h
rc5_skey.o: rc5_locl.h rc5_skey.c
rc5cfb64.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc5.h
rc5cfb64.o: rc5_locl.h rc5cfb64.c
rc5ofb64.o: ../../include/openssl/opensslconf.h ../../include/openssl/rc5.h
rc5ofb64.o: rc5_locl.h rc5ofb64.c
