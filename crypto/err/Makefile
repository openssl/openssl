#
# OpenSSL/crypto/err/Makefile
#

INCLUDES_crypto_err= -Icrypto -I. -Iinclude

CFLAGS_crypto_err= $(INCLUDES_crypto_err) $(CFLAG)

GENERAL_crypto_err=crypto/err/Makefile
TEST_crypto_err=
APPS_crypto_err=

LIB_crypto_err=libcrypto.a
LIBSRC_crypto_err=crypto/err/err.c crypto/err/err_all.c crypto/err/err_prn.c
LIBOBJ_crypto_err=crypto/err/err.o crypto/err/err_all.o crypto/err/err_prn.o

SRC_crypto_err= $(LIBSRC_crypto_err)

EXHEADER_crypto_err= crypto/err/err.h
HEADER_crypto_err=	$(EXHEADER_crypto_err)

ALL_crypto_err=    $(GENERAL_crypto_err) $(SRC_crypto_err) $(HEADER_crypto_err)


all: all_crypto_err
all_crypto_err:	crypto/err/lib

crypto/err/lib:	$(LIBOBJ_crypto_err)
	$(ARX) $(LIB_crypto_err) $(LIBOBJ_crypto_err)
	$(RANLIB) $(LIB_crypto_err) || echo Never mind.
	@touch crypto/err/lib

files: files_crypto_err
files_crypto_err:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_err
links_crypto_err:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_err)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_err)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_err)

install: install_crypto_err
install_crypto_err:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_err)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_err
tags_crypto_err:
	ctags $(SRC_crypto_err)

tests: tests_crypto_err
tests_crypto_err:

lint: lint_crypto_err
lint_crypto_err:
	lint -DLINT $(INCLUDES_crypto_err) $(SRC_crypto_err)>crypto/err/fluff

dclean: dclean_crypto_err
dclean_crypto_err:

clean: clean_crypto_err
clean_crypto_err:
	rm -f crypto/err/*.o crypto/err/*.d crypto/err/*.obj crypto/err/lib crypto/err/tags crypto/err/core crypto/err/.pure crypto/err/.nfs* crypto/err/*.old crypto/err/*.bak crypto/err/fluff

