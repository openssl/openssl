#
# OpenSSL/crypto/rc2/Makefile
#


CFLAGS_crypto_rc2= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_rc2=crypto/rc2/Makefile
TEST_crypto_rc2=crypto/rc2/rc2test.c
APPS_crypto_rc2=

LIB_crypto_rc2=libcrypto.a
LIBSRC_crypto_rc2=crypto/rc2/rc2_ecb.c crypto/rc2/rc2_skey.c crypto/rc2/rc2_cbc.c crypto/rc2/rc2cfb64.c crypto/rc2/rc2ofb64.c
LIBOBJ_crypto_rc2=crypto/rc2/rc2_ecb.o crypto/rc2/rc2_skey.o crypto/rc2/rc2_cbc.o crypto/rc2/rc2cfb64.o crypto/rc2/rc2ofb64.o

SRC_crypto_rc2= $(LIBSRC_crypto_rc2)

EXHEADER_crypto_rc2= crypto/rc2/rc2.h
HEADER_crypto_rc2=	crypto/rc2/rc2_locl.h $(EXHEADER_crypto_rc2)

ALL_crypto_rc2=    $(GENERAL_crypto_rc2) $(SRC_crypto_rc2) $(HEADER_crypto_rc2)


all: all_crypto_rc2
all_crypto_rc2:	$(LIBOBJ_crypto_rc2)


files: files_crypto_rc2
files_crypto_rc2:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_rc2
links_crypto_rc2:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_rc2)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_rc2)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_rc2)

install: install_crypto_rc2
install_crypto_rc2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rc2)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc2
tags_crypto_rc2:
	ctags $(SRC_crypto_rc2)

tests: tests_crypto_rc2
tests_crypto_rc2:

lint: lint_crypto_rc2
lint_crypto_rc2:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_rc2)>crypto/rc2/fluff

dclean: dclean_crypto_rc2
dclean_crypto_rc2:

clean: clean_crypto_rc2
clean_crypto_rc2:
	rm -f crypto/rc2/*.o crypto/rc2/*.d crypto/rc2/*.obj crypto/rc2/lib crypto/rc2/tags crypto/rc2/core crypto/rc2/.pure crypto/rc2/.nfs* crypto/rc2/*.old crypto/rc2/*.bak crypto/rc2/fluff

