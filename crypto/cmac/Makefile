#
# OpenSSL/crypto/cmac/Makefile
#

DIR=	cmac
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=cmac.c cm_ameth.c cm_pmeth.c
LIBOBJ=cmac.o cm_ameth.o cm_pmeth.o

SRC= $(LIBSRC)

EXHEADER= cmac.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_cmac
top_crypto_cmac:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_cmac
all_crypto_cmac:	lib

lib: lib_crypto_cmac
lib_crypto_cmac:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_cmac
files_crypto_cmac:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_cmac
links_crypto_cmac:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_cmac
install_crypto_cmac:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cmac
tags_crypto_cmac:
	ctags $(SRC)

tests: tests_crypto_cmac
tests_crypto_cmac:

lint: lint_crypto_cmac
lint_crypto_cmac:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_cmac
dclean_crypto_cmac:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_cmac
clean_crypto_cmac:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

