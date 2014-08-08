#
# crypto/camellia/Makefile
#

CPP_crypto_camellia=	$(CC) -E


CFLAGS_crypto_camellia= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_camellia= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_camellia= $(ASFLAGS_crypto_camellia)

GENERAL_crypto_camellia=crypto/camellia/Makefile
#TEST=camelliatest.c
APPS_crypto_camellia=

LIB_crypto_camellia=libcrypto.a
LIBSRC_crypto_camellia=crypto/camellia/camellia.c crypto/camellia/cmll_misc.c crypto/camellia/cmll_ecb.c crypto/camellia/cmll_cbc.c crypto/camellia/cmll_ofb.c \
	   crypto/camellia/cmll_cfb.c crypto/camellia/cmll_ctr.c 

LIBOBJ_crypto_camellia= crypto/camellia/cmll_ecb.o crypto/camellia/cmll_ofb.o crypto/camellia/cmll_cfb.o crypto/camellia/cmll_ctr.o $(CMLL_ENC)

SRC_crypto_camellia= $(LIBSRC_crypto_camellia)

EXHEADER_crypto_camellia= crypto/camellia/camellia.h
HEADER_crypto_camellia= crypto/camellia/cmll_locl.h $(EXHEADER_crypto_camellia)

ALL_crypto_camellia=    $(GENERAL_crypto_camellia) $(SRC_crypto_camellia) $(HEADER_crypto_camellia)


all: all_crypto_camellia
all_crypto_camellia:	$(LIBOBJ_crypto_camellia)


crypto/camellia/cmll-x86.s:	crypto/camellia/asm/cmll-x86.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/camellia/asm/cmll-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_camellia) $(PROCESSOR) > $@
crypto/camellia/cmll-x86_64.s:  crypto/camellia/asm/cmll-x86_64.pl
	$(PERL) crypto/camellia/asm/cmll-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/camellia/cmllt4-sparcv9.s: crypto/camellia/asm/cmllt4-sparcv9.pl
	$(PERL) crypto/camellia/asm/cmllt4-sparcv9.pl $(CFLAGS_crypto_camellia) > $@

files: files_crypto_camellia
files_crypto_camellia:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_camellia
links_crypto_camellia:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_camellia)
	@$(PERL) util/mklink.pl ./test $(TEST)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_camellia)

install: install_crypto_camellia
install_crypto_camellia:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_camellia)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_camellia
tags_crypto_camellia:
	ctags $(SRC_crypto_camellia)

tests: tests_crypto_camellia
tests_crypto_camellia:

lint: lint_crypto_camellia
lint_crypto_camellia:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_camellia)>crypto/camellia/fluff

dclean: dclean_crypto_camellia
dclean_crypto_camellia:

clean: clean_crypto_camellia
clean_crypto_camellia:
	rm -f crypto/camellia/*.s crypto/camellia/*.o crypto/camellia/*.d crypto/camellia/*.obj crypto/camellia/lib crypto/camellia/tags crypto/camellia/core crypto/camellia/.pure crypto/camellia/.nfs* crypto/camellia/*.old crypto/camellia/*.bak crypto/camellia/fluff

