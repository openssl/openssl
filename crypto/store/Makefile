#
# OpenSSL/crypto/store/Makefile
#


CFLAGS_crypto_store= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_store=crypto/store/Makefile
#TEST= storetest.c
TEST_crypto_store=
APPS_crypto_store=

LIB_crypto_store=libcrypto.a
LIBSRC_crypto_store= crypto/store/str_err.c crypto/store/str_lib.c crypto/store/str_meth.c crypto/store/str_mem.c
LIBOBJ_crypto_store= crypto/store/str_err.o crypto/store/str_lib.o crypto/store/str_meth.o crypto/store/str_mem.o

SRC_crypto_store= $(LIBSRC_crypto_store)

#EXHEADER= store.h str_compat.h
EXHEADER_crypto_store= crypto/store/store.h
HEADER_crypto_store=	$(EXHEADER_crypto_store) crypto/store/str_locl.h

ALL_crypto_store=    $(GENERAL_crypto_store) $(SRC_crypto_store) $(HEADER_crypto_store)


all: all_crypto_store
all_crypto_store:	crypto/store/lib

crypto/store/lib:	$(LIBOBJ_crypto_store)
	$(ARX) $(LIB_crypto_store) $(LIBOBJ_crypto_store)
	$(RANLIB) $(LIB_crypto_store) || echo Never mind.
	@touch crypto/store/lib

files: files_crypto_store
files_crypto_store:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_store
links_crypto_store:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_store)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_store)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_store)

install: install_crypto_store
install_crypto_store:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_store)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_store
tags_crypto_store:
	ctags $(SRC_crypto_store)

tests: tests_crypto_store
tests_crypto_store:

lint: lint_crypto_store
lint_crypto_store:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_store)>crypto/store/fluff

dclean: dclean_crypto_store
dclean_crypto_store:

clean: clean_crypto_store
clean_crypto_store:
	rm -f crypto/store/*.o crypto/store/*.d */*.o */*.d crypto/store/*.obj crypto/store/lib crypto/store/tags crypto/store/core crypto/store/.pure crypto/store/.nfs* crypto/store/*.old crypto/store/*.bak crypto/store/fluff

