#
# crypto/whrlpool/Makefile
#

CPP_crypto_whrlpool=	$(CC) -E


CFLAGS_crypto_whrlpool= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_whrlpool= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_whrlpool= $(ASFLAGS_crypto_whrlpool)

GENERAL_crypto_whrlpool=crypto/whrlpool/Makefile
TEST_crypto_whrlpool=crypto/whrlpool/wp_test.c
APPS_crypto_whrlpool=

LIB_crypto_whrlpool=libcrypto.a
LIBSRC_crypto_whrlpool=crypto/whrlpool/wp_dgst.c crypto/whrlpool/wp_block.c
LIBOBJ_crypto_whrlpool=crypto/whrlpool/wp_dgst.o $(WP_ASM_OBJ)

SRC_crypto_whrlpool= $(LIBSRC_crypto_whrlpool)

EXHEADER_crypto_whrlpool= crypto/whrlpool/whrlpool.h
HEADER_crypto_whrlpool= crypto/whrlpool/wp_locl.h $(EXHEADER_crypto_whrlpool)

ALL_crypto_whrlpool=    $(GENERAL_crypto_whrlpool) $(SRC_crypto_whrlpool) $(HEADER_crypto_whrlpool)


all: all_crypto_whrlpool
all_crypto_whrlpool:	$(LIBOBJ_crypto_whrlpool)


crypto/whrlpool/wp-mmx.s:	crypto/whrlpool/asm/wp-mmx.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/whrlpool/asm/wp-mmx.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_whrlpool) $(PROCESSOR) > $@

crypto/whrlpool/wp-x86_64.s: crypto/whrlpool/asm/wp-x86_64.pl
	$(PERL) crypto/whrlpool/asm/wp-x86_64.pl $(PERLASM_SCHEME) > $@

$(LIBOBJ_crypto_whrlpool): $(LIBSRC_crypto_whrlpool)

files: files_crypto_whrlpool
files_crypto_whrlpool:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_whrlpool
links_crypto_whrlpool:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_whrlpool)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_whrlpool)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_whrlpool)

install: install_crypto_whrlpool
install_crypto_whrlpool:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_whrlpool)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_whrlpool
tags_crypto_whrlpool:
	ctags $(SRC_crypto_whrlpool)

tests: tests_crypto_whrlpool
tests_crypto_whrlpool:

lint: lint_crypto_whrlpool
lint_crypto_whrlpool:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_whrlpool)>crypto/whrlpool/fluff

dclean: dclean_crypto_whrlpool
dclean_crypto_whrlpool:

clean: clean_crypto_whrlpool
clean_crypto_whrlpool:
	rm -f crypto/whrlpool/*.s crypto/whrlpool/*.o crypto/whrlpool/*.d crypto/whrlpool/*.obj crypto/whrlpool/lib crypto/whrlpool/tags crypto/whrlpool/core crypto/whrlpool/.pure crypto/whrlpool/.nfs* crypto/whrlpool/*.old crypto/whrlpool/*.bak crypto/whrlpool/fluff

