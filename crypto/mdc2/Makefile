#
# OpenSSL/crypto/mdc2/Makefile
#


CFLAGS_crypto_mdc2= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_mdc2=crypto/mdc2/Makefile
TEST_crypto_mdc2= crypto/mdc2/mdc2test.c
APPS_crypto_mdc2=

LIB_crypto_mdc2=libcrypto.a
LIBSRC_crypto_mdc2=crypto/mdc2/mdc2dgst.c crypto/mdc2/mdc2_one.c
LIBOBJ_crypto_mdc2=crypto/mdc2/mdc2dgst.o crypto/mdc2/mdc2_one.o

SRC_crypto_mdc2= $(LIBSRC_crypto_mdc2)

EXHEADER_crypto_mdc2= crypto/mdc2/mdc2.h
HEADER_crypto_mdc2=	$(EXHEADER_crypto_mdc2)

ALL_crypto_mdc2=    $(GENERAL_crypto_mdc2) $(SRC_crypto_mdc2) $(HEADER_crypto_mdc2)


all: all_crypto_mdc2
all_crypto_mdc2:	$(LIBOBJ_crypto_mdc2)


files: files_crypto_mdc2
files_crypto_mdc2:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_mdc2
links_crypto_mdc2:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_mdc2)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_mdc2)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_mdc2)

install: install_crypto_mdc2
install_crypto_mdc2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_mdc2)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_mdc2
tags_crypto_mdc2:
	ctags $(SRC_crypto_mdc2)

tests: tests_crypto_mdc2
tests_crypto_mdc2:

lint: lint_crypto_mdc2
lint_crypto_mdc2:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_mdc2)>crypto/mdc2/fluff

dclean: dclean_crypto_mdc2
dclean_crypto_mdc2:

clean: clean_crypto_mdc2
clean_crypto_mdc2:
	rm -f crypto/mdc2/*.o crypto/mdc2/*.d crypto/mdc2/*.obj crypto/mdc2/lib crypto/mdc2/tags crypto/mdc2/core crypto/mdc2/.pure crypto/mdc2/.nfs* crypto/mdc2/*.old crypto/mdc2/*.bak crypto/mdc2/fluff

