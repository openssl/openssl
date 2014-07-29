#
# OpenSSL/crypto/md/Makefile
#

INCLUDES_crypto_hmac=

CFLAGS_crypto_hmac= $(INCLUDES_crypto_hmac) $(CFLAG)

GENERAL_crypto_hmac=crypto/hmac/Makefile
TEST_crypto_hmac=crypto/hmac/hmactest.c
APPS_crypto_hmac=

LIB_crypto_hmac=libcrypto.a
LIBSRC_crypto_hmac=crypto/hmac/hmac.c crypto/hmac/hm_ameth.c crypto/hmac/hm_pmeth.c
LIBOBJ_crypto_hmac=crypto/hmac/hmac.o crypto/hmac/hm_ameth.o crypto/hmac/hm_pmeth.o

SRC_crypto_hmac= $(LIBSRC_crypto_hmac)

EXHEADER_crypto_hmac= crypto/hmac/hmac.h
HEADER_crypto_hmac=	$(EXHEADER_crypto_hmac)

ALL_crypto_hmac=    $(GENERAL_crypto_hmac) $(SRC_crypto_hmac) $(HEADER_crypto_hmac)


all: all_crypto_hmac
all_crypto_hmac:	crypto/hmac/lib

crypto/hmac/lib:	$(LIBOBJ_crypto_hmac)
	$(ARX) $(LIB_crypto_hmac) $(LIBOBJ_crypto_hmac)
	$(RANLIB) $(LIB_crypto_hmac) || echo Never mind.
	@touch crypto/hmac/lib

files: files_crypto_hmac
files_crypto_hmac:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_hmac
links_crypto_hmac:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_hmac)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_hmac)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_hmac)

install: install_crypto_hmac
install_crypto_hmac:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_hmac)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_hmac
tags_crypto_hmac:
	ctags $(SRC_crypto_hmac)

tests: tests_crypto_hmac
tests_crypto_hmac:

lint: lint_crypto_hmac
lint_crypto_hmac:
	lint -DLINT $(INCLUDES_crypto_hmac) $(SRC_crypto_hmac)>crypto/hmac/fluff

dclean: dclean_crypto_hmac
dclean_crypto_hmac:

clean: clean_crypto_hmac
clean_crypto_hmac:
	rm -f crypto/hmac/*.o crypto/hmac/*.d crypto/hmac/*.obj crypto/hmac/lib crypto/hmac/tags crypto/hmac/core crypto/hmac/.pure crypto/hmac/.nfs* crypto/hmac/*.old crypto/hmac/*.bak crypto/hmac/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_hmac) $(CPPFLAGS) -c -o $@ $<
