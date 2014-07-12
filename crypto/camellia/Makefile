#
# crypto/camellia/Makefile
#

DIR= camellia
CPP=	$(CC) -E
INCLUDES=


CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
#TEST=camelliatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=camellia.c cmll_misc.c cmll_ecb.c cmll_cbc.c cmll_ofb.c \
	   cmll_cfb.c cmll_ctr.c 

LIBOBJ= cmll_ecb.o cmll_ofb.o cmll_cfb.o cmll_ctr.o $(CMLL_ENC)

SRC= $(LIBSRC)

EXHEADER= camellia.h
HEADER= cmll_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_camellia
top_crypto_camellia:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_camellia
all_crypto_camellia:	lib

lib: lib_crypto_camellia
lib_crypto_camellia:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

cmll-x86.s:	asm/cmll-x86.pl ../perlasm/x86asm.pl
	$(PERL) asm/cmll-x86.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
cmll-x86_64.s:  asm/cmll-x86_64.pl
	$(PERL) asm/cmll-x86_64.pl $(PERLASM_SCHEME) > $@
cmllt4-sparcv9.s: asm/cmllt4-sparcv9.pl
	$(PERL) asm/cmllt4-sparcv9.pl $(CFLAGS) > $@

files: files_crypto_camellia
files_crypto_camellia:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_camellia
links_crypto_camellia:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_camellia
install_crypto_camellia:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_camellia
tags_crypto_camellia:
	ctags $(SRC)

tests: tests_crypto_camellia
tests_crypto_camellia:

lint: lint_crypto_camellia
lint_crypto_camellia:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_camellia
dclean_crypto_camellia:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_camellia
clean_crypto_camellia:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

