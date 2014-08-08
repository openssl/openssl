#
# crypto/seed/Makefile
#

CPP_crypto_seed=	$(CC) -E
INCLUDES_crypto_seed=

CFLAGS_crypto_seed= $(INCLUDES_crypto_seed) $(CFLAG)

GENERAL_crypto_seed=crypto/seed/Makefile
TEST_crypto_seed=
APPS_crypto_seed=

LIB_crypto_seed=libcrypto.a
LIBSRC_crypto_seed=crypto/seed/seed.c crypto/seed/seed_ecb.c crypto/seed/seed_cbc.c crypto/seed/seed_cfb.c crypto/seed/seed_ofb.c
LIBOBJ_crypto_seed=crypto/seed/seed.o crypto/seed/seed_ecb.o crypto/seed/seed_cbc.o crypto/seed/seed_cfb.o crypto/seed/seed_ofb.o

SRC_crypto_seed= $(LIBSRC_crypto_seed)

EXHEADER_crypto_seed= crypto/seed/seed.h
HEADER_crypto_seed= crypto/seed/seed_locl.h $(EXHEADER_crypto_seed)

ALL_crypto_seed=    $(GENERAL_crypto_seed) $(SRC_crypto_seed) $(HEADER_crypto_seed)


all: all_crypto_seed
all_crypto_seed:	crypto/seed/lib

crypto/seed/lib:	$(LIBOBJ_crypto_seed)
	$(ARX) $(LIB_crypto_seed) $(LIBOBJ_crypto_seed)
	$(RANLIB) $(LIB_crypto_seed) || echo Never mind.
	@touch crypto/seed/lib

files: files_crypto_seed
files_crypto_seed:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_seed
links_crypto_seed:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_seed)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_seed)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_seed)

install: install_crypto_seed
install_crypto_seed:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_seed)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_seed
tags_crypto_seed:
	ctags $(SRC_crypto_seed)

tests: tests_crypto_seed
tests_crypto_seed:

lint: lint_crypto_seed
lint_crypto_seed:
	lint -DLINT $(INCLUDES_crypto_seed) $(SRC_crypto_seed)>crypto/seed/fluff

dclean: dclean_crypto_seed
dclean_crypto_seed:

clean: clean_crypto_seed
clean_crypto_seed:
	rm -f crypto/seed/*.o crypto/seed/*.d crypto/seed/*.obj crypto/seed/lib crypto/seed/tags crypto/seed/core crypto/seed/.pure crypto/seed/.nfs* crypto/seed/*.old crypto/seed/*.bak crypto/seed/fluff

