#
# OpenSSL/crypto/modes/Makefile
#



CFLAGS_crypto_modes= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_modes= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_modes= $(ASFLAGS_crypto_modes)

GENERAL_crypto_modes=crypto/modes/Makefile
TEST_crypto_modes=
APPS_crypto_modes=

LIB_crypto_modes=libcrypto.a
LIBSRC_crypto_modes= crypto/modes/cbc128.c crypto/modes/ctr128.c crypto/modes/cts128.c crypto/modes/cfb128.c crypto/modes/ofb128.c crypto/modes/gcm128.c \
	crypto/modes/ccm128.c crypto/modes/xts128.c crypto/modes/wrap128.c
LIBOBJ_crypto_modes= crypto/modes/cbc128.o crypto/modes/ctr128.o crypto/modes/cts128.o crypto/modes/cfb128.o crypto/modes/ofb128.o crypto/modes/gcm128.o \
	crypto/modes/ccm128.o crypto/modes/xts128.o crypto/modes/wrap128.o $(MODES_ASM_OBJ)

SRC_crypto_modes= $(LIBSRC_crypto_modes)

#EXHEADER= store.h str_compat.h
EXHEADER_crypto_modes= crypto/modes/modes.h
HEADER_crypto_modes=	crypto/modes/modes_lcl.h $(EXHEADER_crypto_modes)

ALL_crypto_modes=    $(GENERAL_crypto_modes) $(SRC_crypto_modes) $(HEADER_crypto_modes)


all: all_crypto_modes
all_crypto_modes:	crypto/modes/lib

crypto/modes/lib:	$(LIBOBJ_crypto_modes)
	$(ARX) $(LIB_crypto_modes) $(LIBOBJ_crypto_modes)
	$(RANLIB) $(LIB_crypto_modes) || echo Never mind.
	@touch crypto/modes/lib

crypto/modes/ghash-ia64.s:	crypto/modes/asm/ghash-ia64.pl
	$(PERL) crypto/modes/asm/ghash-ia64.pl $@ $(CFLAGS_crypto_modes)
crypto/modes/ghash-x86.s:	crypto/modes/asm/ghash-x86.pl
	$(PERL) crypto/modes/asm/ghash-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_modes) $(PROCESSOR) > $@
crypto/modes/ghash-x86_64.s:	crypto/modes/asm/ghash-x86_64.pl
	$(PERL) crypto/modes/asm/ghash-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/modes/aesni-gcm-x86_64.s:	crypto/modes/asm/aesni-gcm-x86_64.pl
	$(PERL) crypto/modes/asm/aesni-gcm-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/modes/ghash-sparcv9.s:	crypto/modes/asm/ghash-sparcv9.pl
	$(PERL) crypto/modes/asm/ghash-sparcv9.pl $@ $(CFLAGS_crypto_modes)
crypto/modes/ghash-alpha.s:	crypto/modes/asm/ghash-alpha.pl
	(preproc=/tmp/$$$$.$@; trap "rm $$preproc" INT; \
	$(PERL) crypto/modes/asm/ghash-alpha.pl > $$preproc && \
	$(CC) -E $$preproc > $@ && rm $$preproc)
crypto/modes/ghash-parisc.s:	crypto/modes/asm/ghash-parisc.pl
	$(PERL) crypto/modes/asm/ghash-parisc.pl $(PERLASM_SCHEME) $@
crypto/modes/ghashv8-armx.S:	crypto/modes/asm/ghashv8-armx.pl
	$(PERL) crypto/modes/asm/ghashv8-armx.pl $(PERLASM_SCHEME) $@
crypto/modes/ghashp8-ppc.s:	crypto/modes/asm/ghashp8-ppc.pl
	$(PERL) crypto/modes/asm/ghashp8-ppc.pl $(PERLASM_SCHEME) $@

# GNU make "catch all"
crypto/modes/ghash-%.S:	crypto/modes/asm/ghash-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

crypto/modes/ghash-armv4.o:	crypto/modes/ghash-armv4.S
crypto/modes/ghashv8-armx.o:	crypto/modes/ghashv8-armx.S

files: files_crypto_modes
files_crypto_modes:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_modes
links_crypto_modes:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_modes)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_modes)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_modes)

install: install_crypto_modes
install_crypto_modes:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_modes)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_modes
tags_crypto_modes:
	ctags $(SRC_crypto_modes)

tests: tests_crypto_modes
tests_crypto_modes:

lint: lint_crypto_modes
lint_crypto_modes:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_modes)>crypto/modes/fluff

dclean: dclean_crypto_modes
dclean_crypto_modes:

clean: clean_crypto_modes
clean_crypto_modes:
	rm -f crypto/modes/*.s crypto/modes/*.o crypto/modes/*.d */*.o */*.d crypto/modes/*.obj crypto/modes/lib crypto/modes/tags crypto/modes/core crypto/modes/.pure crypto/modes/.nfs* crypto/modes/*.old crypto/modes/*.bak crypto/modes/fluff

