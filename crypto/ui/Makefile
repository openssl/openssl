#
# OpenSSL/crypto/ui/Makefile
#


CFLAGS_crypto_ui= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_ui=crypto/ui/Makefile
#TEST= uitest.c
TEST_crypto_ui=
APPS_crypto_ui=

COMPATSRC= crypto/ui/ui_compat.c
COMPATOBJ= crypto/ui/ui_compat.o

LIB_crypto_ui=libcrypto.a
LIBSRC_crypto_ui= crypto/ui/ui_err.c crypto/ui/ui_lib.c crypto/ui/ui_openssl.c crypto/ui/ui_util.c $(COMPATSRC)
LIBOBJ_crypto_ui= crypto/ui/ui_err.o crypto/ui/ui_lib.o crypto/ui/ui_openssl.o crypto/ui/ui_util.o $(COMPATOBJ)

SRC_crypto_ui= $(LIBSRC_crypto_ui)

EXHEADER_crypto_ui= crypto/ui/ui.h crypto/ui/ui_compat.h
HEADER_crypto_ui=	$(EXHEADER_crypto_ui) crypto/ui/ui_locl.h

ALL_crypto_ui=    $(GENERAL_crypto_ui) $(SRC_crypto_ui) $(HEADER_crypto_ui)


all: all_crypto_ui
all_crypto_ui:	crypto/ui/lib

crypto/ui/lib:	$(LIBOBJ_crypto_ui)
	$(ARX) $(LIB_crypto_ui) $(LIBOBJ_crypto_ui)
	$(RANLIB) $(LIB_crypto_ui) || echo Never mind.
	@touch crypto/ui/lib

files: files_crypto_ui
files_crypto_ui:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ui
links_crypto_ui:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ui)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ui)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ui)

install: install_crypto_ui
install_crypto_ui:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ui)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ui
tags_crypto_ui:
	ctags $(SRC_crypto_ui)

tests: tests_crypto_ui
tests_crypto_ui:

lint: lint_crypto_ui
lint_crypto_ui:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_ui)>crypto/ui/fluff

dclean: dclean_crypto_ui
dclean_crypto_ui:

clean: clean_crypto_ui
clean_crypto_ui:
	rm -f crypto/ui/*.o crypto/ui/*.d */*.o */*.d crypto/ui/*.obj crypto/ui/lib crypto/ui/tags crypto/ui/core crypto/ui/.pure crypto/ui/.nfs* crypto/ui/*.old crypto/ui/*.bak crypto/ui/fluff

