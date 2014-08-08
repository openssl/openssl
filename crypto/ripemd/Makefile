#
# OpenSSL/crypto/ripemd/Makefile
#

CPP_crypto_ripemd=    $(CC) -E

RIP_ASM_OBJ=

CFLAGS_crypto_ripemd= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_ripemd= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_ripemd= $(ASFLAGS_crypto_ripemd)

GENERAL_crypto_ripemd=crypto/ripemd/Makefile
TEST_crypto_ripemd=crypto/ripemd/rmdtest.c
APPS_crypto_ripemd=

LIB_crypto_ripemd=libcrypto.a
LIBSRC_crypto_ripemd=crypto/ripemd/rmd_dgst.c crypto/ripemd/rmd_one.c
LIBOBJ_crypto_ripemd=crypto/ripemd/rmd_dgst.o crypto/ripemd/rmd_one.o $(RMD160_ASM_OBJ)

SRC_crypto_ripemd= $(LIBSRC_crypto_ripemd)

EXHEADER_crypto_ripemd= crypto/ripemd/ripemd.h
HEADER_crypto_ripemd= crypto/ripemd/rmd_locl.h crypto/ripemd/rmdconst.h $(EXHEADER_crypto_ripemd)

ALL_crypto_ripemd=    $(GENERAL_crypto_ripemd) $(SRC_crypto_ripemd) $(HEADER_crypto_ripemd)


all: all_crypto_ripemd
all_crypto_ripemd:    $(LIBOBJ_crypto_ripemd)


crypto/ripemd/rmd-586.s:	crypto/ripemd/asm/rmd-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/ripemd/asm/rmd-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_ripemd) > $@

files: files_crypto_ripemd
files_crypto_ripemd:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ripemd
links_crypto_ripemd:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ripemd)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ripemd)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ripemd)

install: install_crypto_ripemd
install_crypto_ripemd:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ripemd)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ripemd
tags_crypto_ripemd:
	ctags $(SRC_crypto_ripemd)

tests: tests_crypto_ripemd
tests_crypto_ripemd:

lint: lint_crypto_ripemd
lint_crypto_ripemd:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_ripemd)>crypto/ripemd/fluff

dclean: dclean_crypto_ripemd
dclean_crypto_ripemd:

clean: clean_crypto_ripemd
clean_crypto_ripemd:
	rm -f crypto/ripemd/*.s crypto/ripemd/*.o crypto/ripemd/*.d crypto/ripemd/*.obj crypto/ripemd/lib crypto/ripemd/tags crypto/ripemd/core crypto/ripemd/.pure crypto/ripemd/.nfs* crypto/ripemd/*.old crypto/ripemd/*.bak crypto/ripemd/fluff

