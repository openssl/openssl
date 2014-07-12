#
# OpenSSL/crypto/rc2/Makefile
#

DIR=	rc2
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=rc2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc2_ecb.c rc2_skey.c rc2_cbc.c rc2cfb64.c rc2ofb64.c
LIBOBJ=rc2_ecb.o rc2_skey.o rc2_cbc.o rc2cfb64.o rc2ofb64.o

SRC= $(LIBSRC)

EXHEADER= rc2.h
HEADER=	rc2_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_rc2
top_crypto_rc2:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_rc2
all_crypto_rc2:	lib

lib: lib_crypto_rc2
lib_crypto_rc2:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_rc2
files_crypto_rc2:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_rc2
links_crypto_rc2:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_rc2
install_crypto_rc2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc2
tags_crypto_rc2:
	ctags $(SRC)

tests: tests_crypto_rc2
tests_crypto_rc2:

lint: lint_crypto_rc2
lint_crypto_rc2:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_rc2
dclean_crypto_rc2:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_rc2
clean_crypto_rc2:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

