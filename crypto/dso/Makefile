#
# OpenSSL/crypto/dso/Makefile
#

INCLUDES_crypto_dso= -Icrypto -I. -Iinclude

CFLAGS_crypto_dso= $(INCLUDES_crypto_dso) $(CFLAG)

GENERAL_crypto_dso=crypto/dso/Makefile
TEST_crypto_dso=
APPS_crypto_dso=

LIB_crypto_dso=libcrypto.a
LIBSRC_crypto_dso= crypto/dso/dso_dl.c crypto/dso/dso_dlfcn.c crypto/dso/dso_err.c crypto/dso/dso_lib.c crypto/dso/dso_null.c \
	crypto/dso/dso_openssl.c crypto/dso/dso_win32.c crypto/dso/dso_vms.c crypto/dso/dso_beos.c
LIBOBJ_crypto_dso= crypto/dso/dso_dl.o crypto/dso/dso_dlfcn.o crypto/dso/dso_err.o crypto/dso/dso_lib.o crypto/dso/dso_null.o \
	crypto/dso/dso_openssl.o crypto/dso/dso_win32.o crypto/dso/dso_vms.o crypto/dso/dso_beos.o

SRC_crypto_dso= $(LIBSRC_crypto_dso)

EXHEADER_crypto_dso= crypto/dso/dso.h
HEADER_crypto_dso=	$(EXHEADER_crypto_dso)

ALL_crypto_dso=    $(GENERAL_crypto_dso) $(SRC_crypto_dso) $(HEADER_crypto_dso)


all: all_crypto_dso
all_crypto_dso:	crypto/dso/lib

crypto/dso/lib:	$(LIBOBJ_crypto_dso)
	$(ARX) $(LIB_crypto_dso) $(LIBOBJ_crypto_dso)
	$(RANLIB) $(LIB_crypto_dso) || echo Never mind.
	@touch crypto/dso/lib

files: files_crypto_dso
files_crypto_dso:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_dso
links_crypto_dso:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_dso)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_dso)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_dso)

install: install_crypto_dso
install_crypto_dso:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_dso)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_dso
tags_crypto_dso:
	ctags $(SRC_crypto_dso)

tests: tests_crypto_dso
tests_crypto_dso:

lint: lint_crypto_dso
lint_crypto_dso:
	lint -DLINT $(INCLUDES_crypto_dso) $(SRC_crypto_dso)>crypto/dso/fluff

dclean: dclean_crypto_dso
dclean_crypto_dso:

clean: clean_crypto_dso
clean_crypto_dso:
	rm -f crypto/dso/*.o crypto/dso/*.d */*.o */*.d crypto/dso/*.obj crypto/dso/lib crypto/dso/tags crypto/dso/core crypto/dso/.pure crypto/dso/.nfs* crypto/dso/*.old crypto/dso/*.bak crypto/dso/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_dso) $(CPPFLAGS) -c -o $@ $<
