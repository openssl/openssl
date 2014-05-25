#
# OpenSSL/crypto/idea/Makefile
#

DIR=	idea
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=ideatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=i_cbc.c i_cfb64.c i_ofb64.c i_ecb.c i_skey.c
LIBOBJ=i_cbc.o i_cfb64.o i_ofb64.o i_ecb.o i_skey.o

SRC= $(LIBSRC)

EXHEADER= idea.h
HEADER=	idea_lcl.h $(EXHEADER)

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

i_cbc.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_cbc.o: i_cbc.c idea_lcl.h
i_cfb64.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_cfb64.o: i_cfb64.c idea_lcl.h
i_ecb.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_ecb.o: ../../include/openssl/opensslv.h i_ecb.c idea_lcl.h
i_ofb64.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_ofb64.o: i_ofb64.c idea_lcl.h
i_skey.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_skey.o: i_skey.c idea_lcl.h
