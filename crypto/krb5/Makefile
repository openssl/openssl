#
# OpenSSL/krb5/Makefile
#

DIR=	krb5
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= krb5_asn.c

LIBOBJ= krb5_asn.o

SRC= $(LIBSRC)

EXHEADER= krb5_asn.h
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
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean: dclean_common

clean: clean_common

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

krb5_asn.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
krb5_asn.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
krb5_asn.o: ../../include/openssl/e_os2.h ../../include/openssl/krb5_asn.h
krb5_asn.o: ../../include/openssl/opensslconf.h
krb5_asn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
krb5_asn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
krb5_asn.o: ../../include/openssl/symhacks.h krb5_asn.c
