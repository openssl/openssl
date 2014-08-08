#
# OpenSSL/crypto/md5/Makefile
#

CPP_crypto_md5=    $(CC) -E


CFLAGS_crypto_md5= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_md5= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_md5= $(ASFLAGS_crypto_md5)

GENERAL_crypto_md5=crypto/md5/Makefile
TEST_crypto_md5=crypto/md5/md5test.c
APPS_crypto_md5=

LIB_crypto_md5=libcrypto.a
LIBSRC_crypto_md5=crypto/md5/md5_dgst.c crypto/md5/md5_one.c
LIBOBJ_crypto_md5=crypto/md5/md5_dgst.o crypto/md5/md5_one.o $(MD5_ASM_OBJ)

SRC_crypto_md5= $(LIBSRC_crypto_md5)

EXHEADER_crypto_md5= crypto/md5/md5.h
HEADER_crypto_md5= crypto/md5/md5_locl.h $(EXHEADER_crypto_md5)

ALL_crypto_md5=    $(GENERAL_crypto_md5) $(SRC_crypto_md5) $(HEADER_crypto_md5)


all: all_crypto_md5
all_crypto_md5:    crypto/md5/lib

crypto/md5/lib:    $(LIBOBJ_crypto_md5)
	$(ARX) $(LIB_crypto_md5) $(LIBOBJ_crypto_md5)
	$(RANLIB) $(LIB_crypto_md5) || echo Never mind.
	@touch crypto/md5/lib

crypto/md5/md5-586.s:	crypto/md5/asm/md5-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/md5/asm/md5-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_md5) > $@

crypto/md5/md5-x86_64.s:	crypto/md5/asm/md5-x86_64.pl
	$(PERL) crypto/md5/asm/md5-x86_64.pl $(PERLASM_SCHEME) > $@

crypto/md5/md5-ia64.s: crypto/md5/asm/md5-ia64.S
	$(CC) $(CFLAGS_crypto_md5) -E crypto/md5/asm/md5-ia64.S | \
	$(PERL) -ne 's/;\s+/;\n/g; print;' > $@

crypto/md5/md5-sparcv9.S:	crypto/md5/asm/md5-sparcv9.pl
	$(PERL) crypto/md5/asm/md5-sparcv9.pl $@ $(CFLAGS_crypto_md5)

files: files_crypto_md5
files_crypto_md5:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_md5
links_crypto_md5:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_md5)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_md5)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_md5)

install: install_crypto_md5
install_crypto_md5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_md5)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_md5
tags_crypto_md5:
	ctags $(SRC_crypto_md5)

tests: tests_crypto_md5
tests_crypto_md5:

lint: lint_crypto_md5
lint_crypto_md5:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_md5)>crypto/md5/fluff

dclean: dclean_crypto_md5
dclean_crypto_md5:

clean: clean_crypto_md5
clean_crypto_md5:
	rm -f crypto/md5/*.s crypto/md5/*.o crypto/md5/*.d crypto/md5/*.obj crypto/md5/lib crypto/md5/tags crypto/md5/core crypto/md5/.pure crypto/md5/.nfs* crypto/md5/*.old crypto/md5/*.bak crypto/md5/fluff

