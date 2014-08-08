#
# OpenSSL/crypto/sha/Makefile
#

CPP_crypto_sha=    $(CC) -E


CFLAGS_crypto_sha= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_sha= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_sha= $(ASFLAGS_crypto_sha)

GENERAL_crypto_sha=crypto/sha/Makefile
TEST_crypto_sha=crypto/sha/shatest.c crypto/sha/sha1test.c crypto/sha/sha256t.c crypto/sha/sha512t.c
APPS_crypto_sha=

LIB_crypto_sha=libcrypto.a
LIBSRC_crypto_sha=crypto/sha/sha_dgst.c crypto/sha/sha1dgst.c crypto/sha/sha_one.c crypto/sha/sha1_one.c crypto/sha/sha256.c crypto/sha/sha512.c
LIBOBJ_crypto_sha=crypto/sha/sha_dgst.o crypto/sha/sha1dgst.o crypto/sha/sha_one.o crypto/sha/sha1_one.o crypto/sha/sha256.o crypto/sha/sha512.o $(SHA1_ASM_OBJ)

SRC_crypto_sha= $(LIBSRC_crypto_sha)

EXHEADER_crypto_sha= crypto/sha/sha.h
HEADER_crypto_sha= crypto/sha/sha_locl.h $(EXHEADER_crypto_sha)

ALL_crypto_sha=    $(GENERAL_crypto_sha) $(SRC_crypto_sha) $(HEADER_crypto_sha)


all: all_crypto_sha
all_crypto_sha:    crypto/sha/lib

crypto/sha/lib:    $(LIBOBJ_crypto_sha)
	$(ARX) $(LIB_crypto_sha) $(LIBOBJ_crypto_sha)
	$(RANLIB) $(LIB_crypto_sha) || echo Never mind.
	@touch crypto/sha/lib

crypto/sha/sha1-586.s:	crypto/sha/asm/sha1-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/sha/asm/sha1-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_sha) $(PROCESSOR) > $@
crypto/sha/sha256-586.s:	crypto/sha/asm/sha256-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/sha/asm/sha256-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_sha) $(PROCESSOR) > $@
crypto/sha/sha512-586.s:	crypto/sha/asm/sha512-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/sha/asm/sha512-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_sha) $(PROCESSOR) > $@

crypto/sha/sha1-ia64.s:   crypto/sha/asm/sha1-ia64.pl
	$(PERL) crypto/sha/asm/sha1-ia64.pl $@ $(CFLAGS_crypto_sha)
crypto/sha/sha256-ia64.s: crypto/sha/asm/sha512-ia64.pl
	$(PERL) crypto/sha/asm/sha512-ia64.pl $@ $(CFLAGS_crypto_sha)
crypto/sha/sha512-ia64.s: crypto/sha/asm/sha512-ia64.pl
	$(PERL) crypto/sha/asm/sha512-ia64.pl $@ $(CFLAGS_crypto_sha)

crypto/sha/sha256-armv4.S: crypto/sha/asm/sha256-armv4.pl
	$(PERL) $< $(PERLASM_SCHEME) $@

crypto/sha/sha1-alpha.s:	crypto/sha/asm/sha1-alpha.pl
	(preproc=/tmp/$$$$.$@; trap "rm $$preproc" INT; \
	$(PERL) crypto/sha/asm/sha1-alpha.pl > $$preproc && \
	$(CC) -E $$preproc > $@ && rm $$preproc)

# Solaris make has to be explicitly told
crypto/sha/sha1-x86_64.s:	crypto/sha/asm/sha1-x86_64.pl;	$(PERL) crypto/sha/asm/sha1-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/sha/sha1-mb-x86_64.s:	crypto/sha/asm/sha1-mb-x86_64.pl;	$(PERL) crypto/sha/asm/sha1-mb-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/sha/sha256-x86_64.s:crypto/sha/asm/sha512-x86_64.pl;	$(PERL) crypto/sha/asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
crypto/sha/sha256-mb-x86_64.s:	crypto/sha/asm/sha256-mb-x86_64.pl;	$(PERL) crypto/sha/asm/sha256-mb-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/sha/sha512-x86_64.s:crypto/sha/asm/sha512-x86_64.pl;	$(PERL) crypto/sha/asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
crypto/sha/sha1-sparcv9.S:	crypto/sha/asm/sha1-sparcv9.pl;	$(PERL) crypto/sha/asm/sha1-sparcv9.pl $@ $(CFLAGS_crypto_sha)
crypto/sha/sha256-sparcv9.S:crypto/sha/asm/sha512-sparcv9.pl;	$(PERL) crypto/sha/asm/sha512-sparcv9.pl $@ $(CFLAGS_crypto_sha)
crypto/sha/sha512-sparcv9.S:crypto/sha/asm/sha512-sparcv9.pl;	$(PERL) crypto/sha/asm/sha512-sparcv9.pl $@ $(CFLAGS_crypto_sha)

crypto/sha/sha1-ppc.s:	crypto/sha/asm/sha1-ppc.pl;	$(PERL) crypto/sha/asm/sha1-ppc.pl $(PERLASM_SCHEME) $@
crypto/sha/sha256-ppc.s:	crypto/sha/asm/sha512-ppc.pl;	$(PERL) crypto/sha/asm/sha512-ppc.pl $(PERLASM_SCHEME) $@
crypto/sha/sha512-ppc.s:	crypto/sha/asm/sha512-ppc.pl;	$(PERL) crypto/sha/asm/sha512-ppc.pl $(PERLASM_SCHEME) $@
crypto/sha/sha256p8-ppc.s:	crypto/sha/asm/sha512p8-ppc.pl;	$(PERL) crypto/sha/asm/sha512p8-ppc.pl $(PERLASM_SCHEME) $@
crypto/sha/sha512p8-ppc.s:	crypto/sha/asm/sha512p8-ppc.pl;	$(PERL) crypto/sha/asm/sha512p8-ppc.pl $(PERLASM_SCHEME) $@

crypto/sha/sha1-parisc.s:	crypto/sha/asm/sha1-parisc.pl;	$(PERL) crypto/sha/asm/sha1-parisc.pl $(PERLASM_SCHEME) $@
crypto/sha/sha256-parisc.s:crypto/sha/asm/sha512-parisc.pl;	$(PERL) crypto/sha/asm/sha512-parisc.pl $(PERLASM_SCHEME) $@
crypto/sha/sha512-parisc.s:crypto/sha/asm/sha512-parisc.pl;	$(PERL) crypto/sha/asm/sha512-parisc.pl $(PERLASM_SCHEME) $@

crypto/sha/sha1-mips.S:	crypto/sha/asm/sha1-mips.pl;	$(PERL) crypto/sha/asm/sha1-mips.pl $(PERLASM_SCHEME) $@
crypto/sha/sha256-mips.S:	crypto/sha/asm/sha512-mips.pl;	$(PERL) crypto/sha/asm/sha512-mips.pl $(PERLASM_SCHEME) $@
crypto/sha/sha512-mips.S:	crypto/sha/asm/sha512-mips.pl;	$(PERL) crypto/sha/asm/sha512-mips.pl $(PERLASM_SCHEME) $@

# GNU make "catch all"
crypto/sha/sha1-%.S:	crypto/sha/asm/sha1-%.pl;		$(PERL) $< $(PERLASM_SCHEME) $@
crypto/sha/sha256-%.S:	crypto/sha/asm/sha512-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
crypto/sha/sha512-%.S:	crypto/sha/asm/sha512-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

crypto/sha/sha1-armv4-large.o:	crypto/sha/sha1-armv4-large.S
crypto/sha/sha256-armv4.o:		crypto/sha/sha256-armv4.S
crypto/sha/sha512-armv4.o:		crypto/sha/sha512-armv4.S
crypto/sha/sha1-armv8.o:		crypto/sha/sha1-armv8.S
crypto/sha/sha256-armv8.o:		crypto/sha/sha256-armv8.S
crypto/sha/sha512-armv8.o:		crypto/sha/sha512-armv8.S

files: files_crypto_sha
files_crypto_sha:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_sha
links_crypto_sha:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_sha)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_sha)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_sha)

install: install_crypto_sha
install_crypto_sha:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_sha)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_sha
tags_crypto_sha:
	ctags $(SRC_crypto_sha)

tests: tests_crypto_sha
tests_crypto_sha:

lint: lint_crypto_sha
lint_crypto_sha:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_sha)>crypto/sha/fluff

dclean: dclean_crypto_sha
dclean_crypto_sha:

clean: clean_crypto_sha
clean_crypto_sha:
	rm -f crypto/sha/*.s crypto/sha/*.o crypto/sha/*.d crypto/sha/*.obj crypto/sha/lib crypto/sha/tags crypto/sha/core crypto/sha/.pure crypto/sha/.nfs* crypto/sha/*.old crypto/sha/*.bak crypto/sha/fluff

