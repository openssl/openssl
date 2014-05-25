#
# OpenSSL/crypto/cast/Makefile
#

DIR=	cast
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CAST_ENC=c_enc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=casttest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=c_skey.c c_ecb.c c_enc.c c_cfb64.c c_ofb64.c 
LIBOBJ=c_skey.o c_ecb.o $(CAST_ENC) c_cfb64.o c_ofb64.o

SRC= $(LIBSRC)

EXHEADER= cast.h
HEADER=	cast_s.h cast_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib: lib_arx_common

cast-586.s:	asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL)	asm/cast-586.pl $(PERLASM_SCHEME) $(CLAGS) $(PROCESSOR) > $@

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

c_cfb64.o: ../../e_os.h ../../include/openssl/cast.h
c_cfb64.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_cfb64.o: c_cfb64.c cast_lcl.h
c_ecb.o: ../../e_os.h ../../include/openssl/cast.h
c_ecb.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_ecb.o: ../../include/openssl/opensslv.h c_ecb.c cast_lcl.h
c_enc.o: ../../e_os.h ../../include/openssl/cast.h
c_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_enc.o: c_enc.c cast_lcl.h
c_ofb64.o: ../../e_os.h ../../include/openssl/cast.h
c_ofb64.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_ofb64.o: c_ofb64.c cast_lcl.h
c_skey.o: ../../e_os.h ../../include/openssl/cast.h
c_skey.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_skey.o: c_skey.c cast_lcl.h cast_s.h
