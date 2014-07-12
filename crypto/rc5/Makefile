#
# OpenSSL/crypto/rc5/Makefile
#

DIR=	rc5
CPP=	$(CC) -E
INCLUDES=


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

top: top_crypto_rc5
top_crypto_rc5:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_rc5
all_crypto_rc5:	lib

lib: lib_crypto_rc5
lib_crypto_rc5:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

rc5-586.s: asm/rc5-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/rc5-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

files: files_crypto_rc5
files_crypto_rc5:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_rc5
links_crypto_rc5:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_rc5
install_crypto_rc5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc5
tags_crypto_rc5:
	ctags $(SRC)

tests: tests_crypto_rc5
tests_crypto_rc5:

lint: lint_crypto_rc5
lint_crypto_rc5:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_rc5
dclean_crypto_rc5:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_rc5
clean_crypto_rc5:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

