#
# OpenSSL/crypto/pkcs7/Makefile
#

DIR=	pkcs7
INCLUDES= -I.. -I$(TOP) -I../../include

 
CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	pk7_asn1.c pk7_lib.c pkcs7err.c pk7_doit.c pk7_smime.c pk7_attr.c \
	pk7_mime.c bio_pk7.c
LIBOBJ= pk7_asn1.o pk7_lib.o pkcs7err.o pk7_doit.o pk7_smime.o pk7_attr.o \
	pk7_mime.o bio_pk7.o

SRC= $(LIBSRC)

EXHEADER=  pkcs7.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_pkcs7
top_crypto_pkcs7:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test: test_crypto_pkcs7
test_crypto_pkcs7:

all: all_crypto_pkcs7
all_crypto_pkcs7:	lib

lib: lib_crypto_pkcs7
lib_crypto_pkcs7:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_pkcs7
files_crypto_pkcs7:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_pkcs7
links_crypto_pkcs7:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_pkcs7
install_crypto_pkcs7:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pkcs7
tags_crypto_pkcs7:
	ctags $(SRC)

tests: tests_crypto_pkcs7
tests_crypto_pkcs7:

lint: lint_crypto_pkcs7
lint_crypto_pkcs7:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_pkcs7
dclean_crypto_pkcs7:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_pkcs7
clean_crypto_pkcs7:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff enc dec sign verify

