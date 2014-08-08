#
# OpenSSL/crypto/dsa/Makefile
#


CFLAGS_crypto_dsa= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_dsa=crypto/dsa/Makefile
TEST_crypto_dsa=crypto/dsa/dsatest.c
APPS_crypto_dsa=

LIB_crypto_dsa=libcrypto.a
LIBSRC_crypto_dsa= crypto/dsa/dsa_gen.c crypto/dsa/dsa_key.c crypto/dsa/dsa_lib.c crypto/dsa/dsa_asn1.c crypto/dsa/dsa_vrf.c crypto/dsa/dsa_sign.c \
	crypto/dsa/dsa_err.c crypto/dsa/dsa_ossl.c crypto/dsa/dsa_depr.c crypto/dsa/dsa_ameth.c crypto/dsa/dsa_pmeth.c crypto/dsa/dsa_prn.c
LIBOBJ_crypto_dsa= crypto/dsa/dsa_gen.o crypto/dsa/dsa_key.o crypto/dsa/dsa_lib.o crypto/dsa/dsa_asn1.o crypto/dsa/dsa_vrf.o crypto/dsa/dsa_sign.o \
	crypto/dsa/dsa_err.o crypto/dsa/dsa_ossl.o crypto/dsa/dsa_depr.o crypto/dsa/dsa_ameth.o crypto/dsa/dsa_pmeth.o crypto/dsa/dsa_prn.o

SRC_crypto_dsa= $(LIBSRC_crypto_dsa)

EXHEADER_crypto_dsa= crypto/dsa/dsa.h
HEADER_crypto_dsa=	crypto/dsa/dsa_locl.h $(EXHEADER_crypto_dsa)

ALL_crypto_dsa=    $(GENERAL_crypto_dsa) $(SRC_crypto_dsa) $(HEADER_crypto_dsa)


all: all_crypto_dsa
all_crypto_dsa:	crypto/dsa/lib

crypto/dsa/lib:	$(LIBOBJ_crypto_dsa)
	$(ARX) $(LIB_crypto_dsa) $(LIBOBJ_crypto_dsa)
	$(RANLIB) $(LIB_crypto_dsa) || echo Never mind.
	@touch crypto/dsa/lib

files: files_crypto_dsa
files_crypto_dsa:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_dsa
links_crypto_dsa:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_dsa)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_dsa)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_dsa)

install: install_crypto_dsa
install_crypto_dsa:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_dsa)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_dsa
tags_crypto_dsa:
	ctags $(SRC_crypto_dsa)

tests: tests_crypto_dsa
tests_crypto_dsa:

lint: lint_crypto_dsa
lint_crypto_dsa:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_dsa)>crypto/dsa/fluff

dclean: dclean_crypto_dsa
dclean_crypto_dsa:

clean: clean_crypto_dsa
clean_crypto_dsa:
	rm -f crypto/dsa/*.o crypto/dsa/*.d */*.o */*.d crypto/dsa/*.obj crypto/dsa/lib crypto/dsa/tags crypto/dsa/core crypto/dsa/.pure crypto/dsa/.nfs* crypto/dsa/*.old crypto/dsa/*.bak crypto/dsa/fluff

