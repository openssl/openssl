#
# crypto/ecdh/Makefile
#

DIR=	ecdh
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=ecdhtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	ech_lib.c ech_ossl.c ech_key.c ech_err.c ech_kdf.c

LIBOBJ=	ech_lib.o ech_ossl.o ech_key.o ech_err.o ech_kdf.o

SRC= $(LIBSRC)

EXHEADER= ecdh.h
HEADER=	ech_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_ecdh
top_crypto_ecdh:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_ecdh
all_crypto_ecdh:	lib

lib: lib_crypto_ecdh
lib_crypto_ecdh:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_ecdh
files_crypto_ecdh:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_ecdh
links_crypto_ecdh:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_ecdh
install_crypto_ecdh:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ecdh
tags_crypto_ecdh:
	ctags $(SRC)

tests: tests_crypto_ecdh
tests_crypto_ecdh:

lint: lint_crypto_ecdh
lint_crypto_ecdh:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_ecdh
dclean_crypto_ecdh:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_ecdh
clean_crypto_ecdh:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

