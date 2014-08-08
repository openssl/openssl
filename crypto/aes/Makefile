#
# crypto/aes/Makefile
#

CPP_crypto_aes=	$(CC) -E
INCLUDES_crypto_aes=


CFLAGS_crypto_aes= $(INCLUDES_crypto_aes) $(CFLAG)
ASFLAGS_crypto_aes= $(INCLUDES_crypto_aes) $(ASFLAG)
AFLAGS_crypto_aes= $(ASFLAGS_crypto_aes)

GENERAL_crypto_aes=crypto/aes/Makefile
#TEST=aestest.c
TEST_crypto_aes=
APPS_crypto_aes=

LIB_crypto_aes=libcrypto.a
LIBSRC_crypto_aes=crypto/aes/aes_core.c crypto/aes/aes_misc.c crypto/aes/aes_ecb.c crypto/aes/aes_cbc.c crypto/aes/aes_cfb.c crypto/aes/aes_ofb.c \
       crypto/aes/aes_ige.c crypto/aes/aes_wrap.c
LIBOBJ_crypto_aes=crypto/aes/aes_misc.o crypto/aes/aes_ecb.o crypto/aes/aes_cfb.o crypto/aes/aes_ofb.o crypto/aes/aes_ige.o crypto/aes/aes_wrap.o \
       $(AES_ENC)

SRC_crypto_aes= $(LIBSRC_crypto_aes)

EXHEADER_crypto_aes= crypto/aes/aes.h
HEADER_crypto_aes= crypto/aes/aes_locl.h $(EXHEADER_crypto_aes)

ALL_crypto_aes=    $(GENERAL_crypto_aes) $(SRC_crypto_aes) $(HEADER_crypto_aes)


all: all_crypto_aes
all_crypto_aes:	crypto/aes/lib

crypto/aes/lib:	$(LIBOBJ_crypto_aes)
	$(ARX) $(LIB_crypto_aes) $(LIBOBJ_crypto_aes)
	$(RANLIB) $(LIB_crypto_aes) || echo Never mind.
	@touch crypto/aes/lib

crypto/aes/aes-ia64.s: crypto/aes/asm/aes-ia64.S
	$(CC) $(CFLAGS_crypto_aes) -E crypto/aes/asm/aes-ia64.S > $@

crypto/aes/aes-586.s:	crypto/aes/asm/aes-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/aes/asm/aes-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_aes) $(PROCESSOR) > $@
crypto/aes/vpaes-x86.s:	crypto/aes/asm/vpaes-x86.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/aes/asm/vpaes-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_aes) $(PROCESSOR) > $@
crypto/aes/aesni-x86.s:	crypto/aes/asm/aesni-x86.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/aes/asm/aesni-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_aes) $(PROCESSOR) > $@

crypto/aes/aes-x86_64.s: crypto/aes/asm/aes-x86_64.pl
	$(PERL) crypto/aes/asm/aes-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/aes/vpaes-x86_64.s:	crypto/aes/asm/vpaes-x86_64.pl
	$(PERL) crypto/aes/asm/vpaes-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/aes/bsaes-x86_64.s:	crypto/aes/asm/bsaes-x86_64.pl
	$(PERL) crypto/aes/asm/bsaes-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/aes/aesni-x86_64.s: crypto/aes/asm/aesni-x86_64.pl
	$(PERL) crypto/aes/asm/aesni-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/aes/aesni-sha1-x86_64.s:	crypto/aes/asm/aesni-sha1-x86_64.pl
	$(PERL) crypto/aes/asm/aesni-sha1-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/aes/aesni-sha256-x86_64.s:	crypto/aes/asm/aesni-sha256-x86_64.pl
	$(PERL) crypto/aes/asm/aesni-sha256-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/aes/aesni-mb-x86_64.s:	crypto/aes/asm/aesni-mb-x86_64.pl
	$(PERL) crypto/aes/asm/aesni-mb-x86_64.pl $(PERLASM_SCHEME) > $@

crypto/aes/aes-sparcv9.s: crypto/aes/asm/aes-sparcv9.pl
	$(PERL) crypto/aes/asm/aes-sparcv9.pl $(CFLAGS_crypto_aes) > $@
crypto/aes/aest4-sparcv9.s: crypto/aes/asm/aest4-sparcv9.pl
	$(PERL) crypto/aes/asm/aest4-sparcv9.pl $(CFLAGS_crypto_aes) > $@

crypto/aes/aes-ppc.s:	crypto/aes/asm/aes-ppc.pl
	$(PERL) crypto/aes/asm/aes-ppc.pl $(PERLASM_SCHEME) $@
crypto/aes/vpaes-ppc.s:	crypto/aes/asm/vpaes-ppc.pl
	$(PERL) crypto/aes/asm/vpaes-ppc.pl $(PERLASM_SCHEME) $@
crypto/aes/aesp8-ppc.s:	crypto/aes/asm/aesp8-ppc.pl
	$(PERL) crypto/aes/asm/aesp8-ppc.pl $(PERLASM_SCHEME) $@

crypto/aes/aes-parisc.s:	crypto/aes/asm/aes-parisc.pl
	$(PERL) crypto/aes/asm/aes-parisc.pl $(PERLASM_SCHEME) $@

crypto/aes/aes-mips.S:	crypto/aes/asm/aes-mips.pl
	$(PERL) crypto/aes/asm/aes-mips.pl $(PERLASM_SCHEME) $@

crypto/aes/aesv8-armx.S:	crypto/aes/asm/aesv8-armx.pl
	$(PERL) crypto/aes/asm/aesv8-armx.pl $(PERLASM_SCHEME) $@
crypto/aes/aesv8-armx.o:	crypto/aes/aesv8-armx.S

# GNU make "catch all"
crypto/aes/aes-%.S:	crypto/aes/asm/aes-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
crypto/aes/aes-armv4.o:	crypto/aes/aes-armv4.S
crypto/aes/bsaes-%.S:	crypto/aes/asm/bsaes-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
crypto/aes/bsaes-armv7.o:	crypto/aes/bsaes-armv7.S

files: files_crypto_aes
files_crypto_aes:
	$(PERL) util/files.pl TOP=. "AES_ENC=$(AES_ENC)" Makefile >> MINFO

links: links_crypto_aes
links_crypto_aes:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_aes)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_aes)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_aes)

install: install_crypto_aes
install_crypto_aes:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_aes)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_aes
tags_crypto_aes:
	ctags $(SRC_crypto_aes)

tests: tests_crypto_aes
tests_crypto_aes:

lint: lint_crypto_aes
lint_crypto_aes:
	lint -DLINT $(INCLUDES_crypto_aes) $(SRC_crypto_aes)>crypto/aes/fluff

dclean: dclean_crypto_aes
dclean_crypto_aes:

clean: clean_crypto_aes
clean_crypto_aes:
	rm -f crypto/aes/*.s crypto/aes/*.o crypto/aes/*.d crypto/aes/*.obj crypto/aes/lib crypto/aes/tags crypto/aes/core crypto/aes/.pure crypto/aes/.nfs* crypto/aes/*.old crypto/aes/*.bak crypto/aes/fluff

