#
# OpenSSL/crypto/pkcs12/Makefile
#

DIR=	pkcs12
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= p12_add.c p12_asn.c p12_attr.c p12_crpt.c p12_crt.c p12_decr.c \
	p12_init.c p12_key.c p12_kiss.c p12_mutl.c\
	p12_utl.c p12_npas.c pk12err.c p12_p8d.c p12_p8e.c
LIBOBJ= p12_add.o p12_asn.o p12_attr.o p12_crpt.o p12_crt.o p12_decr.o \
	p12_init.o p12_key.o p12_kiss.o p12_mutl.o\
	p12_utl.o p12_npas.o pk12err.o p12_p8d.o p12_p8e.o

SRC= $(LIBSRC)

EXHEADER=  pkcs12.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_pkcs12
top_crypto_pkcs12:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test: test_crypto_pkcs12
test_crypto_pkcs12:

all: all_crypto_pkcs12
all_crypto_pkcs12:	lib

lib: lib_crypto_pkcs12
lib_crypto_pkcs12:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_pkcs12
files_crypto_pkcs12:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_pkcs12
links_crypto_pkcs12:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_pkcs12
install_crypto_pkcs12:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pkcs12
tags_crypto_pkcs12:
	ctags $(SRC)

tests: tests_crypto_pkcs12
tests_crypto_pkcs12:

lint: lint_crypto_pkcs12
lint_crypto_pkcs12:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_pkcs12
dclean_crypto_pkcs12:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_pkcs12
clean_crypto_pkcs12:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

