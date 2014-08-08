#
# OpenSSL/crypto/idea/Makefile
#

INCLUDES_crypto_idea=

CFLAGS_crypto_idea= $(INCLUDES_crypto_idea) $(CFLAG)

GENERAL_crypto_idea=crypto/idea/Makefile
TEST_crypto_idea=crypto/idea/ideatest.c
APPS_crypto_idea=

LIB_crypto_idea=libcrypto.a
LIBSRC_crypto_idea=crypto/idea/i_cbc.c crypto/idea/i_cfb64.c crypto/idea/i_ofb64.c crypto/idea/i_ecb.c crypto/idea/i_skey.c
LIBOBJ_crypto_idea=crypto/idea/i_cbc.o crypto/idea/i_cfb64.o crypto/idea/i_ofb64.o crypto/idea/i_ecb.o crypto/idea/i_skey.o

SRC_crypto_idea= $(LIBSRC_crypto_idea)

EXHEADER_crypto_idea= crypto/idea/idea.h
HEADER_crypto_idea=	crypto/idea/idea_lcl.h $(EXHEADER_crypto_idea)

ALL_crypto_idea=    $(GENERAL_crypto_idea) $(SRC_crypto_idea) $(HEADER_crypto_idea)


all: all_crypto_idea
all_crypto_idea:	crypto/idea/lib

crypto/idea/lib:	$(LIBOBJ_crypto_idea)
	$(ARX) $(LIB_crypto_idea) $(LIBOBJ_crypto_idea)
	$(RANLIB) $(LIB_crypto_idea) || echo Never mind.
	@touch crypto/idea/lib

files: files_crypto_idea
files_crypto_idea:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_idea
links_crypto_idea:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_idea)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_idea)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_idea)

install: install_crypto_idea
install_crypto_idea:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_idea)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_idea
tags_crypto_idea:
	ctags $(SRC_crypto_idea)

tests: tests_crypto_idea
tests_crypto_idea:

lint: lint_crypto_idea
lint_crypto_idea:
	lint -DLINT $(INCLUDES_crypto_idea) $(SRC_crypto_idea)>crypto/idea/fluff

dclean: dclean_crypto_idea
dclean_crypto_idea:

clean: clean_crypto_idea
clean_crypto_idea:
	rm -f crypto/idea/*.o crypto/idea/*.d crypto/idea/*.obj crypto/idea/lib crypto/idea/tags crypto/idea/core crypto/idea/.pure crypto/idea/.nfs* crypto/idea/*.old crypto/idea/*.bak crypto/idea/fluff

