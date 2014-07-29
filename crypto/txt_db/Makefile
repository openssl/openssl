#
# OpenSSL/crypto/txt_db/Makefile
#

INCLUDES_crypto_txt_db=

CFLAGS_crypto_txt_db= $(INCLUDES_crypto_txt_db) $(CFLAG)

GENERAL_crypto_txt_db=crypto/txt_db/Makefile
TEST_crypto_txt_db=
APPS_crypto_txt_db=

LIB_crypto_txt_db=libcrypto.a
LIBSRC_crypto_txt_db=crypto/txt_db/txt_db.c
LIBOBJ_crypto_txt_db=crypto/txt_db/txt_db.o

SRC_crypto_txt_db= $(LIBSRC_crypto_txt_db)

EXHEADER_crypto_txt_db= crypto/txt_db/txt_db.h
HEADER_crypto_txt_db=	$(EXHEADER_crypto_txt_db)

ALL_crypto_txt_db=    $(GENERAL_crypto_txt_db) $(SRC_crypto_txt_db) $(HEADER_crypto_txt_db)


all: all_crypto_txt_db
all_crypto_txt_db:	crypto/txt_db/lib

crypto/txt_db/lib:	$(LIBOBJ_crypto_txt_db)
	$(ARX) $(LIB_crypto_txt_db) $(LIBOBJ_crypto_txt_db)
	$(RANLIB) $(LIB_crypto_txt_db) || echo Never mind.
	@touch crypto/txt_db/lib

files: files_crypto_txt_db
files_crypto_txt_db:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_txt_db
links_crypto_txt_db:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_txt_db)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_txt_db)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_txt_db)

install: install_crypto_txt_db
install_crypto_txt_db:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_txt_db)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_txt_db
tags_crypto_txt_db:
	ctags $(SRC_crypto_txt_db)

tests: tests_crypto_txt_db
tests_crypto_txt_db:

lint: lint_crypto_txt_db
lint_crypto_txt_db:
	lint -DLINT $(INCLUDES_crypto_txt_db) $(SRC_crypto_txt_db)>crypto/txt_db/fluff

dclean: dclean_crypto_txt_db
dclean_crypto_txt_db:

clean: clean_crypto_txt_db
clean_crypto_txt_db:
	rm -f crypto/txt_db/*.o crypto/txt_db/*.d crypto/txt_db/*.obj crypto/txt_db/lib crypto/txt_db/tags crypto/txt_db/core crypto/txt_db/.pure crypto/txt_db/.nfs* crypto/txt_db/*.old crypto/txt_db/*.bak crypto/txt_db/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_txt_db) $(CPPFLAGS) -c -o $@ $<
