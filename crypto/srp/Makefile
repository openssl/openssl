
CFLAGS_crypto_srp= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_srp=crypto/srp/Makefile
TEST_crypto_srp=crypto/srp/srptest.c
APPS_crypto_srp=

LIB_crypto_srp=libcrypto.a
LIBSRC_crypto_srp=crypto/srp/srp_lib.c crypto/srp/srp_vfy.c
LIBOBJ_crypto_srp=crypto/srp/srp_lib.o crypto/srp/srp_vfy.o

SRC_crypto_srp= $(LIBSRC_crypto_srp)

EXHEADER_crypto_srp= crypto/srp/srp.h
HEADER_crypto_srp=	$(EXHEADER_crypto_srp)


all: all_crypto_srp
all_crypto_srp:	$(LIBOBJ_crypto_srp)


files: files_crypto_srp
files_crypto_srp:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_srp
links_crypto_srp:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_srp)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_srp)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_srp)

install: install_crypto_srp
install_crypto_srp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_srp)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_srp
tags_crypto_srp:
	ctags $(SRC_crypto_srp)

tests: tests_crypto_srp
tests_crypto_srp:

lint: lint_crypto_srp
lint_crypto_srp:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_srp)>crypto/srp/fluff

dclean: dclean_crypto_srp
dclean_crypto_srp:

clean: clean_crypto_srp
clean_crypto_srp:
	rm -f crypto/srp/*.o crypto/srp/*.d crypto/srp/*.obj crypto/srp/lib crypto/srp/tags crypto/srp/core crypto/srp/.pure crypto/srp/.nfs* crypto/srp/*.old crypto/srp/*.bak crypto/srp/fluff

