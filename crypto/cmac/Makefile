#
# OpenSSL/crypto/cmac/Makefile
#


CFLAGS_crypto_cmac= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_cmac=crypto/cmac/Makefile
TEST_crypto_cmac=
APPS_crypto_cmac=

LIB_crypto_cmac=libcrypto.a
LIBSRC_crypto_cmac=crypto/cmac/cmac.c crypto/cmac/cm_ameth.c crypto/cmac/cm_pmeth.c
LIBOBJ_crypto_cmac=crypto/cmac/cmac.o crypto/cmac/cm_ameth.o crypto/cmac/cm_pmeth.o

SRC_crypto_cmac= $(LIBSRC_crypto_cmac)

EXHEADER_crypto_cmac= crypto/cmac/cmac.h
HEADER_crypto_cmac=	$(EXHEADER_crypto_cmac)

ALL_crypto_cmac=    $(GENERAL_crypto_cmac) $(SRC_crypto_cmac) $(HEADER_crypto_cmac)


all: all_crypto_cmac
all_crypto_cmac:	crypto/cmac/lib

crypto/cmac/lib:	$(LIBOBJ_crypto_cmac)
	$(ARX) $(LIB_crypto_cmac) $(LIBOBJ_crypto_cmac)
	$(RANLIB) $(LIB_crypto_cmac) || echo Never mind.
	@touch crypto/cmac/lib

files: files_crypto_cmac
files_crypto_cmac:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_cmac
links_crypto_cmac:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_cmac)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_cmac)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_cmac)

install: install_crypto_cmac
install_crypto_cmac:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_cmac)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cmac
tags_crypto_cmac:
	ctags $(SRC_crypto_cmac)

tests: tests_crypto_cmac
tests_crypto_cmac:

lint: lint_crypto_cmac
lint_crypto_cmac:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_cmac)>crypto/cmac/fluff

dclean: dclean_crypto_cmac
dclean_crypto_cmac:

clean: clean_crypto_cmac
clean_crypto_cmac:
	rm -f crypto/cmac/*.o crypto/cmac/*.d crypto/cmac/*.obj crypto/cmac/lib crypto/cmac/tags crypto/cmac/core crypto/cmac/.pure crypto/cmac/.nfs* crypto/cmac/*.old crypto/cmac/*.bak crypto/cmac/fluff

