#
# OpenSSL/krb5/Makefile
#


CFLAGS_crypto_krb5= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_krb5=crypto/krb5/Makefile crypto/krb5/README
TEST_crypto_krb5=
APPS_crypto_krb5=

LIB_crypto_krb5=libcrypto.a
LIBSRC_crypto_krb5= crypto/krb5/krb5_asn.c

LIBOBJ_crypto_krb5= crypto/krb5/krb5_asn.o

SRC_crypto_krb5= $(LIBSRC_crypto_krb5)

EXHEADER_crypto_krb5= crypto/krb5/krb5_asn.h
HEADER_crypto_krb5=	$(EXHEADER_crypto_krb5)

ALL_crypto_krb5=    $(GENERAL_crypto_krb5) $(SRC_crypto_krb5) $(HEADER_crypto_krb5)


all: all_crypto_krb5
all_crypto_krb5:	$(LIBOBJ_crypto_krb5)


files: files_crypto_krb5
files_crypto_krb5:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_krb5
links_crypto_krb5:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_krb5)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_krb5)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_krb5)

install: install_crypto_krb5
install_crypto_krb5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_krb5)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_krb5
tags_crypto_krb5:
	ctags $(SRC_crypto_krb5)

tests: tests_crypto_krb5
tests_crypto_krb5:

lint: lint_crypto_krb5
lint_crypto_krb5:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_krb5)>crypto/krb5/fluff

dclean: dclean_crypto_krb5
dclean_crypto_krb5:

clean: clean_crypto_krb5
clean_crypto_krb5:
	rm -f crypto/krb5/*.o crypto/krb5/*.d crypto/krb5/*.obj crypto/krb5/lib crypto/krb5/tags crypto/krb5/core crypto/krb5/.pure crypto/krb5/.nfs* crypto/krb5/*.old crypto/krb5/*.bak crypto/krb5/fluff

