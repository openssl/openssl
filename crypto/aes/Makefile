#
# crypto/aes/Makefile
#

DIR_crypto_aes=	aes
CPP_crypto_aes=	$(CC) -E
INCLUDES_crypto_aes=


CFLAGS_crypto_aes= $(INCLUDES_crypto_aes) $(CFLAG)
ASFLAGS_crypto_aes= $(INCLUDES_crypto_aes) $(ASFLAG)
AFLAGS_crypto_aes= $(ASFLAGS_crypto_aes)

GENERAL_crypto_aes=Makefile
#TEST=aestest.c
TEST_crypto_aes=
APPS_crypto_aes=

LIB_crypto_aes=$(TOP_crypto_aes)/libcrypto.a
LIBSRC_crypto_aes=aes_core.c aes_misc.c aes_ecb.c aes_cbc.c aes_cfb.c aes_ofb.c \
       aes_ige.c aes_wrap.c
LIBOBJ_crypto_aes=aes_misc.o aes_ecb.o aes_cfb.o aes_ofb.o aes_ige.o aes_wrap.o \
       $(AES_ENC)

SRC_crypto_aes= $(LIBSRC_crypto_aes)

EXHEADER_crypto_aes= aes.h
HEADER_crypto_aes= aes_locl.h $(EXHEADER_crypto_aes)

ALL_crypto_aes=    $(GENERAL_crypto_aes) $(SRC_crypto_aes) $(HEADER_crypto_aes)

top: top_crypto_aes
top_crypto_aes:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_aes) sub_all)

all: all_crypto_aes
all_crypto_aes:	lib

lib:	$(LIBOBJ_crypto_aes)
	$(ARX) $(LIB_crypto_aes) $(LIBOBJ_crypto_aes)
	$(RANLIB) $(LIB_crypto_aes) || echo Never mind.
	@touch lib

aes-ia64.s: asm/aes-ia64.S
	$(CC) $(CFLAGS_crypto_aes) -E asm/aes-ia64.S > $@

aes-586.s:	asm/aes-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/aes-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_aes) $(PROCESSOR) > $@
vpaes-x86.s:	asm/vpaes-x86.pl ../perlasm/x86asm.pl
	$(PERL) asm/vpaes-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_aes) $(PROCESSOR) > $@
aesni-x86.s:	asm/aesni-x86.pl ../perlasm/x86asm.pl
	$(PERL) asm/aesni-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_aes) $(PROCESSOR) > $@

aes-x86_64.s: asm/aes-x86_64.pl
	$(PERL) asm/aes-x86_64.pl $(PERLASM_SCHEME) > $@
vpaes-x86_64.s:	asm/vpaes-x86_64.pl
	$(PERL) asm/vpaes-x86_64.pl $(PERLASM_SCHEME) > $@
bsaes-x86_64.s:	asm/bsaes-x86_64.pl
	$(PERL) asm/bsaes-x86_64.pl $(PERLASM_SCHEME) > $@
aesni-x86_64.s: asm/aesni-x86_64.pl
	$(PERL) asm/aesni-x86_64.pl $(PERLASM_SCHEME) > $@
aesni-sha1-x86_64.s:	asm/aesni-sha1-x86_64.pl
	$(PERL) asm/aesni-sha1-x86_64.pl $(PERLASM_SCHEME) > $@
aesni-sha256-x86_64.s:	asm/aesni-sha256-x86_64.pl
	$(PERL) asm/aesni-sha256-x86_64.pl $(PERLASM_SCHEME) > $@
aesni-mb-x86_64.s:	asm/aesni-mb-x86_64.pl
	$(PERL) asm/aesni-mb-x86_64.pl $(PERLASM_SCHEME) > $@

aes-sparcv9.s: asm/aes-sparcv9.pl
	$(PERL) asm/aes-sparcv9.pl $(CFLAGS_crypto_aes) > $@
aest4-sparcv9.s: asm/aest4-sparcv9.pl
	$(PERL) asm/aest4-sparcv9.pl $(CFLAGS_crypto_aes) > $@

aes-ppc.s:	asm/aes-ppc.pl
	$(PERL) asm/aes-ppc.pl $(PERLASM_SCHEME) $@
vpaes-ppc.s:	asm/vpaes-ppc.pl
	$(PERL) asm/vpaes-ppc.pl $(PERLASM_SCHEME) $@
aesp8-ppc.s:	asm/aesp8-ppc.pl
	$(PERL) asm/aesp8-ppc.pl $(PERLASM_SCHEME) $@

aes-parisc.s:	asm/aes-parisc.pl
	$(PERL) asm/aes-parisc.pl $(PERLASM_SCHEME) $@

aes-mips.S:	asm/aes-mips.pl
	$(PERL) asm/aes-mips.pl $(PERLASM_SCHEME) $@

aesv8-armx.S:	asm/aesv8-armx.pl
	$(PERL) asm/aesv8-armx.pl $(PERLASM_SCHEME) $@
aesv8-armx.o:	aesv8-armx.S

# GNU make "catch all"
aes-%.S:	asm/aes-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
aes-armv4.o:	aes-armv4.S
bsaes-%.S:	asm/bsaes-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
bsaes-armv7.o:	bsaes-armv7.S

files: files_crypto_aes
files_crypto_aes:
	$(PERL) $(TOP_crypto_aes)/util/files.pl TOP=$(TOP_crypto_aes) "AES_ENC=$(AES_ENC)" Makefile >> $(TOP_crypto_aes)/MINFO

links: links_crypto_aes
links_crypto_aes:
	@$(PERL) $(TOP_crypto_aes)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_aes)
	@$(PERL) $(TOP_crypto_aes)/util/mklink.pl ../../test $(TEST_crypto_aes)
	@$(PERL) $(TOP_crypto_aes)/util/mklink.pl ../../apps $(APPS_crypto_aes)

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
	lint -DLINT $(INCLUDES_crypto_aes) $(SRC_crypto_aes)>fluff

dclean: dclean_crypto_aes
dclean_crypto_aes:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_aes
clean_crypto_aes:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_aes) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_aes) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_aes) -o $@ $<
