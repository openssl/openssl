#
# OpenSSL/crypto/sha/Makefile
#

DIR_crypto_sha=    sha
CPP_crypto_sha=    $(CC) -E
INCLUDES_crypto_sha=


CFLAGS_crypto_sha= $(INCLUDES_crypto_sha) $(CFLAG)
ASFLAGS_crypto_sha= $(INCLUDES_crypto_sha) $(ASFLAG)
AFLAGS_crypto_sha= $(ASFLAGS_crypto_sha)

GENERAL_crypto_sha=Makefile
TEST_crypto_sha=shatest.c sha1test.c sha256t.c sha512t.c
APPS_crypto_sha=

LIB_crypto_sha=$(TOP_crypto_sha)/libcrypto.a
LIBSRC_crypto_sha=sha_dgst.c sha1dgst.c sha_one.c sha1_one.c sha256.c sha512.c
LIBOBJ_crypto_sha=sha_dgst.o sha1dgst.o sha_one.o sha1_one.o sha256.o sha512.o $(SHA1_ASM_OBJ)

SRC_crypto_sha= $(LIBSRC_crypto_sha)

EXHEADER_crypto_sha= sha.h
HEADER_crypto_sha= sha_locl.h $(EXHEADER_crypto_sha)

ALL_crypto_sha=    $(GENERAL_crypto_sha) $(SRC_crypto_sha) $(HEADER_crypto_sha)

top: top_crypto_sha
top_crypto_sha:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_sha) sub_all)

all: all_crypto_sha
all_crypto_sha:    lib

lib:    $(LIBOBJ_crypto_sha)
	$(ARX) $(LIB_crypto_sha) $(LIBOBJ_crypto_sha)
	$(RANLIB) $(LIB_crypto_sha) || echo Never mind.
	@touch lib

sha1-586.s:	asm/sha1-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/sha1-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_sha) $(PROCESSOR) > $@
sha256-586.s:	asm/sha256-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/sha256-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_sha) $(PROCESSOR) > $@
sha512-586.s:	asm/sha512-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/sha512-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_sha) $(PROCESSOR) > $@

sha1-ia64.s:   asm/sha1-ia64.pl
	(cd asm; $(PERL) sha1-ia64.pl ../$@ $(CFLAGS_crypto_sha))
sha256-ia64.s: asm/sha512-ia64.pl
	(cd asm; $(PERL) sha512-ia64.pl ../$@ $(CFLAGS_crypto_sha))
sha512-ia64.s: asm/sha512-ia64.pl
	(cd asm; $(PERL) sha512-ia64.pl ../$@ $(CFLAGS_crypto_sha))

sha256-armv4.S: asm/sha256-armv4.pl
	$(PERL) $< $(PERLASM_SCHEME) $@

sha1-alpha.s:	asm/sha1-alpha.pl
	(preproc=/tmp/$$$$.$@; trap "rm $$preproc" INT; \
	$(PERL) asm/sha1-alpha.pl > $$preproc && \
	$(CC) -E $$preproc > $@ && rm $$preproc)

# Solaris make has to be explicitly told
sha1-x86_64.s:	asm/sha1-x86_64.pl;	$(PERL) asm/sha1-x86_64.pl $(PERLASM_SCHEME) > $@
sha1-mb-x86_64.s:	asm/sha1-mb-x86_64.pl;	$(PERL) asm/sha1-mb-x86_64.pl $(PERLASM_SCHEME) > $@
sha256-x86_64.s:asm/sha512-x86_64.pl;	$(PERL) asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
sha256-mb-x86_64.s:	asm/sha256-mb-x86_64.pl;	$(PERL) asm/sha256-mb-x86_64.pl $(PERLASM_SCHEME) > $@
sha512-x86_64.s:asm/sha512-x86_64.pl;	$(PERL) asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
sha1-sparcv9.S:	asm/sha1-sparcv9.pl;	$(PERL) asm/sha1-sparcv9.pl $@ $(CFLAGS_crypto_sha)
sha256-sparcv9.S:asm/sha512-sparcv9.pl;	$(PERL) asm/sha512-sparcv9.pl $@ $(CFLAGS_crypto_sha)
sha512-sparcv9.S:asm/sha512-sparcv9.pl;	$(PERL) asm/sha512-sparcv9.pl $@ $(CFLAGS_crypto_sha)

sha1-ppc.s:	asm/sha1-ppc.pl;	$(PERL) asm/sha1-ppc.pl $(PERLASM_SCHEME) $@
sha256-ppc.s:	asm/sha512-ppc.pl;	$(PERL) asm/sha512-ppc.pl $(PERLASM_SCHEME) $@
sha512-ppc.s:	asm/sha512-ppc.pl;	$(PERL) asm/sha512-ppc.pl $(PERLASM_SCHEME) $@
sha256p8-ppc.s:	asm/sha512p8-ppc.pl;	$(PERL) asm/sha512p8-ppc.pl $(PERLASM_SCHEME) $@
sha512p8-ppc.s:	asm/sha512p8-ppc.pl;	$(PERL) asm/sha512p8-ppc.pl $(PERLASM_SCHEME) $@

sha1-parisc.s:	asm/sha1-parisc.pl;	$(PERL) asm/sha1-parisc.pl $(PERLASM_SCHEME) $@
sha256-parisc.s:asm/sha512-parisc.pl;	$(PERL) asm/sha512-parisc.pl $(PERLASM_SCHEME) $@
sha512-parisc.s:asm/sha512-parisc.pl;	$(PERL) asm/sha512-parisc.pl $(PERLASM_SCHEME) $@

sha1-mips.S:	asm/sha1-mips.pl;	$(PERL) asm/sha1-mips.pl $(PERLASM_SCHEME) $@
sha256-mips.S:	asm/sha512-mips.pl;	$(PERL) asm/sha512-mips.pl $(PERLASM_SCHEME) $@
sha512-mips.S:	asm/sha512-mips.pl;	$(PERL) asm/sha512-mips.pl $(PERLASM_SCHEME) $@

# GNU make "catch all"
sha1-%.S:	asm/sha1-%.pl;		$(PERL) $< $(PERLASM_SCHEME) $@
sha256-%.S:	asm/sha512-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
sha512-%.S:	asm/sha512-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

sha1-armv4-large.o:	sha1-armv4-large.S
sha256-armv4.o:		sha256-armv4.S
sha512-armv4.o:		sha512-armv4.S
sha1-armv8.o:		sha1-armv8.S
sha256-armv8.o:		sha256-armv8.S
sha512-armv8.o:		sha512-armv8.S

files: files_crypto_sha
files_crypto_sha:
	$(PERL) $(TOP_crypto_sha)/util/files.pl TOP=$(TOP_crypto_sha) Makefile >> $(TOP_crypto_sha)/MINFO

links: links_crypto_sha
links_crypto_sha:
	@$(PERL) $(TOP_crypto_sha)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_sha)
	@$(PERL) $(TOP_crypto_sha)/util/mklink.pl ../../test $(TEST_crypto_sha)
	@$(PERL) $(TOP_crypto_sha)/util/mklink.pl ../../apps $(APPS_crypto_sha)

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
	lint -DLINT $(INCLUDES_crypto_sha) $(SRC_crypto_sha)>fluff

dclean: dclean_crypto_sha
dclean_crypto_sha:

clean: clean_crypto_sha
clean_crypto_sha:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_sha) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_sha) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_sha) -o $@ $<
