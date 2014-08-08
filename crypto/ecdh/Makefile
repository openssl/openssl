#
# crypto/ecdh/Makefile
#


CFLAGS_crypto_ecdh= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_ecdh=crypto/ecdh/Makefile
TEST_crypto_ecdh=crypto/ecdh/ecdhtest.c
APPS_crypto_ecdh=

LIB_crypto_ecdh=libcrypto.a
LIBSRC_crypto_ecdh=	crypto/ecdh/ech_lib.c crypto/ecdh/ech_ossl.c crypto/ecdh/ech_key.c crypto/ecdh/ech_err.c crypto/ecdh/ech_kdf.c

LIBOBJ_crypto_ecdh=	crypto/ecdh/ech_lib.o crypto/ecdh/ech_ossl.o crypto/ecdh/ech_key.o crypto/ecdh/ech_err.o crypto/ecdh/ech_kdf.o

SRC_crypto_ecdh= $(LIBSRC_crypto_ecdh)

EXHEADER_crypto_ecdh= crypto/ecdh/ecdh.h
HEADER_crypto_ecdh=	crypto/ecdh/ech_locl.h $(EXHEADER_crypto_ecdh)

ALL_crypto_ecdh=    $(GENERAL_crypto_ecdh) $(SRC_crypto_ecdh) $(HEADER_crypto_ecdh)


all: all_crypto_ecdh
all_crypto_ecdh:	$(LIBOBJ_crypto_ecdh)


files: files_crypto_ecdh
files_crypto_ecdh:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ecdh
links_crypto_ecdh:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ecdh)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ecdh)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ecdh)

install: install_crypto_ecdh
install_crypto_ecdh:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ecdh)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ecdh
tags_crypto_ecdh:
	ctags $(SRC_crypto_ecdh)

tests: tests_crypto_ecdh
tests_crypto_ecdh:

lint: lint_crypto_ecdh
lint_crypto_ecdh:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_ecdh)>crypto/ecdh/fluff

dclean: dclean_crypto_ecdh
dclean_crypto_ecdh:

clean: clean_crypto_ecdh
clean_crypto_ecdh:
	rm -f crypto/ecdh/*.o crypto/ecdh/*.d */*.o */*.d crypto/ecdh/*.obj crypto/ecdh/lib crypto/ecdh/tags crypto/ecdh/core crypto/ecdh/.pure crypto/ecdh/.nfs* crypto/ecdh/*.old crypto/ecdh/*.bak crypto/ecdh/fluff

