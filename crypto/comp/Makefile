#
# OpenSSL/crypto/comp/Makefile
#

INCLUDES_crypto_comp= -Icrypto -I. -Iinclude

CFLAGS_crypto_comp= $(INCLUDES_crypto_comp) $(CFLAG)

GENERAL_crypto_comp=crypto/comp/Makefile
TEST_crypto_comp=
APPS_crypto_comp=

LIB_crypto_comp=libcrypto.a
LIBSRC_crypto_comp= crypto/comp/comp_lib.c crypto/comp/comp_err.c \
	crypto/comp/c_rle.c crypto/comp/c_zlib.c

LIBOBJ_crypto_comp=	crypto/comp/comp_lib.o crypto/comp/comp_err.o \
	crypto/comp/c_rle.o crypto/comp/c_zlib.o

SRC_crypto_comp= $(LIBSRC_crypto_comp)

EXHEADER_crypto_comp= crypto/comp/comp.h
HEADER_crypto_comp=	$(EXHEADER_crypto_comp)

ALL_crypto_comp=    $(GENERAL_crypto_comp) $(SRC_crypto_comp) $(HEADER_crypto_comp)


all: all_crypto_comp
all_crypto_comp:	crypto/comp/lib

crypto/comp/lib:	$(LIBOBJ_crypto_comp)
	$(ARX) $(LIB_crypto_comp) $(LIBOBJ_crypto_comp)
	$(RANLIB) $(LIB_crypto_comp) || echo Never mind.
	@touch crypto/comp/lib

files: files_crypto_comp
files_crypto_comp:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_comp
links_crypto_comp:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_comp)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_comp)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_comp)

install: install_crypto_comp
install_crypto_comp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_comp)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_comp
tags_crypto_comp:
	ctags $(SRC_crypto_comp)

tests: tests_crypto_comp
tests_crypto_comp:

lint: lint_crypto_comp
lint_crypto_comp:
	lint -DLINT $(INCLUDES_crypto_comp) $(SRC_crypto_comp)>crypto/comp/fluff

dclean: dclean_crypto_comp
dclean_crypto_comp:

clean: clean_crypto_comp
clean_crypto_comp:
	rm -f crypto/comp/*.o crypto/comp/*.d crypto/comp/*.obj crypto/comp/lib crypto/comp/tags crypto/comp/core crypto/comp/.pure crypto/comp/.nfs* crypto/comp/*.old crypto/comp/*.bak crypto/comp/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_comp) $(CPPFLAGS) -c -o $@ $<
