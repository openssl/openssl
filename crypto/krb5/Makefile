#
# OpenSSL/krb5/Makefile
#

DIR=	krb5
INCLUDES= -I.. -I$(TOP) -I../../include

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

top: top_crypto_krb5
top_crypto_krb5:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_krb5
all_crypto_krb5:	lib

lib: lib_crypto_krb5
lib_crypto_krb5:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_krb5
files_crypto_krb5:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_krb5
links_crypto_krb5:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_krb5
install_crypto_krb5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_krb5
tags_crypto_krb5:
	ctags $(SRC)

tests: tests_crypto_krb5
tests_crypto_krb5:

lint: lint_crypto_krb5
lint_crypto_krb5:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_krb5
dclean_crypto_krb5:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_krb5
clean_crypto_krb5:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

