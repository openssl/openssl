#
# OpenSSL/crypto/pem/Makefile
#


CFLAGS_crypto_pem= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_pem=crypto/pem/Makefile
TEST_crypto_pem=
APPS_crypto_pem=

LIB_crypto_pem=libcrypto.a
LIBSRC_crypto_pem= crypto/pem/pem_sign.c crypto/pem/pem_seal.c crypto/pem/pem_info.c crypto/pem/pem_lib.c crypto/pem/pem_all.c crypto/pem/pem_err.c \
	crypto/pem/pem_x509.c crypto/pem/pem_xaux.c crypto/pem/pem_oth.c crypto/pem/pem_pk8.c crypto/pem/pem_pkey.c crypto/pem/pvkfmt.c

LIBOBJ_crypto_pem=	crypto/pem/pem_sign.o crypto/pem/pem_seal.o crypto/pem/pem_info.o crypto/pem/pem_lib.o crypto/pem/pem_all.o crypto/pem/pem_err.o \
	crypto/pem/pem_x509.o crypto/pem/pem_xaux.o crypto/pem/pem_oth.o crypto/pem/pem_pk8.o crypto/pem/pem_pkey.o crypto/pem/pvkfmt.o

SRC_crypto_pem= $(LIBSRC_crypto_pem)

EXHEADER_crypto_pem= crypto/pem/pem.h crypto/pem/pem2.h
HEADER_crypto_pem=	$(EXHEADER_crypto_pem)

ALL_crypto_pem=    $(GENERAL_crypto_pem) $(SRC_crypto_pem) $(HEADER_crypto_pem)


all: all_crypto_pem
all_crypto_pem:	$(LIBOBJ_crypto_pem)


files: files_crypto_pem
files_crypto_pem:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_pem
links_crypto_pem: $(EXHEADER_crypto_pem)
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_pem)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_pem)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_pem)

install: install_crypto_pem
install_crypto_pem:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_pem)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pem
tags_crypto_pem:
	ctags $(SRC_crypto_pem)

tests: tests_crypto_pem
tests_crypto_pem:

lint: lint_crypto_pem
lint_crypto_pem:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_pem)>crypto/pem/fluff

dclean: dclean_crypto_pem
dclean_crypto_pem:

clean: clean_crypto_pem
clean_crypto_pem:
	rm -f crypto/pem/*.o crypto/pem/*.d crypto/pem/*.obj crypto/pem/lib crypto/pem/tags crypto/pem/core crypto/pem/.pure crypto/pem/.nfs* crypto/pem/*.old crypto/pem/*.bak crypto/pem/fluff

