#
# OpenSSL/crypto/dh/Makefile
#

INCLUDES_crypto_dh= -Icrypto -I. -Iinclude

CFLAGS_crypto_dh= $(INCLUDES_crypto_dh) $(CFLAG)

GENERAL_crypto_dh=crypto/dh/Makefile
TEST_crypto_dh= crypto/dh/dhtest.c
APPS_crypto_dh=

LIB_crypto_dh=libcrypto.a
LIBSRC_crypto_dh= crypto/dh/dh_asn1.c crypto/dh/dh_gen.c crypto/dh/dh_key.c crypto/dh/dh_lib.c crypto/dh/dh_check.c crypto/dh/dh_err.c crypto/dh/dh_depr.c \
	crypto/dh/dh_ameth.c crypto/dh/dh_pmeth.c crypto/dh/dh_prn.c crypto/dh/dh_rfc5114.c crypto/dh/dh_kdf.c
LIBOBJ_crypto_dh= crypto/dh/dh_asn1.o crypto/dh/dh_gen.o crypto/dh/dh_key.o crypto/dh/dh_lib.o crypto/dh/dh_check.o crypto/dh/dh_err.o crypto/dh/dh_depr.o \
	crypto/dh/dh_ameth.o crypto/dh/dh_pmeth.o crypto/dh/dh_prn.o crypto/dh/dh_rfc5114.o crypto/dh/dh_kdf.o

SRC_crypto_dh= $(LIBSRC_crypto_dh)

EXHEADER_crypto_dh= crypto/dh/dh.h
HEADER_crypto_dh=	$(EXHEADER_crypto_dh)

ALL_crypto_dh=    $(GENERAL_crypto_dh) $(SRC_crypto_dh) $(HEADER_crypto_dh)


all: all_crypto_dh
all_crypto_dh:	crypto/dh/lib

crypto/dh/lib:	$(LIBOBJ_crypto_dh)
	$(ARX) $(LIB_crypto_dh) $(LIBOBJ_crypto_dh)
	$(RANLIB) $(LIB_crypto_dh) || echo Never mind.
	@touch crypto/dh/lib

files: files_crypto_dh
files_crypto_dh:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_dh
links_crypto_dh:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_dh)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_dh)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_dh)

install: install_crypto_dh
install_crypto_dh:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_dh)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_dh
tags_crypto_dh:
	ctags $(SRC_crypto_dh)

tests: tests_crypto_dh
tests_crypto_dh:

lint: lint_crypto_dh
lint_crypto_dh:
	lint -DLINT $(INCLUDES_crypto_dh) $(SRC_crypto_dh)>crypto/dh/fluff

dclean: dclean_crypto_dh
dclean_crypto_dh:

clean: clean_crypto_dh
clean_crypto_dh:
	rm -f crypto/dh/*.o crypto/dh/*.d */*.o */*.d crypto/dh/*.obj crypto/dh/lib crypto/dh/tags crypto/dh/core crypto/dh/.pure crypto/dh/.nfs* crypto/dh/*.old crypto/dh/*.bak crypto/dh/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_dh) $(CPPFLAGS) -c -o $@ $<
