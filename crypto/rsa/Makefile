#
# OpenSSL/crypto/rsa/Makefile
#

INCLUDES_crypto_rsa= -Icrypto -I. -Iinclude

CFLAGS_crypto_rsa= $(INCLUDES_crypto_rsa) $(CFLAG)

GENERAL_crypto_rsa=crypto/rsa/Makefile
TEST_crypto_rsa=crypto/rsa/rsa_test.c
APPS_crypto_rsa=

LIB_crypto_rsa=libcrypto.a
LIBSRC_crypto_rsa= crypto/rsa/rsa_eay.c crypto/rsa/rsa_gen.c crypto/rsa/rsa_lib.c crypto/rsa/rsa_sign.c crypto/rsa/rsa_saos.c crypto/rsa/rsa_err.c \
	crypto/rsa/rsa_pk1.c crypto/rsa/rsa_ssl.c crypto/rsa/rsa_none.c crypto/rsa/rsa_oaep.c crypto/rsa/rsa_chk.c crypto/rsa/rsa_null.c \
	crypto/rsa/rsa_pss.c crypto/rsa/rsa_x931.c crypto/rsa/rsa_asn1.c crypto/rsa/rsa_depr.c crypto/rsa/rsa_ameth.c crypto/rsa/rsa_prn.c \
	crypto/rsa/rsa_pmeth.c crypto/rsa/rsa_crpt.c crypto/rsa/rsa_x931g.c
LIBOBJ_crypto_rsa= crypto/rsa/rsa_eay.o crypto/rsa/rsa_gen.o crypto/rsa/rsa_lib.o crypto/rsa/rsa_sign.o crypto/rsa/rsa_saos.o crypto/rsa/rsa_err.o \
	crypto/rsa/rsa_pk1.o crypto/rsa/rsa_ssl.o crypto/rsa/rsa_none.o crypto/rsa/rsa_oaep.o crypto/rsa/rsa_chk.o crypto/rsa/rsa_null.o \
	crypto/rsa/rsa_pss.o crypto/rsa/rsa_x931.o crypto/rsa/rsa_asn1.o crypto/rsa/rsa_depr.o crypto/rsa/rsa_ameth.o crypto/rsa/rsa_prn.o \
	crypto/rsa/rsa_pmeth.o crypto/rsa/rsa_crpt.o crypto/rsa/rsa_x931g.o

SRC_crypto_rsa= $(LIBSRC_crypto_rsa)

EXHEADER_crypto_rsa= crypto/rsa/rsa.h
HEADER_crypto_rsa=	$(EXHEADER_crypto_rsa)

ALL_crypto_rsa=    $(GENERAL_crypto_rsa) $(SRC_crypto_rsa) $(HEADER_crypto_rsa)


all: all_crypto_rsa
all_crypto_rsa:	crypto/rsa/lib

crypto/rsa/lib:	$(LIBOBJ_crypto_rsa)
	$(ARX) $(LIB_crypto_rsa) $(LIBOBJ_crypto_rsa)
	$(RANLIB) $(LIB_crypto_rsa) || echo Never mind.
	@touch crypto/rsa/lib

files: files_crypto_rsa
files_crypto_rsa:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_rsa
links_crypto_rsa:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_rsa)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_rsa)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_rsa)

install: install_crypto_rsa
install_crypto_rsa:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rsa)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rsa
tags_crypto_rsa:
	ctags $(SRC_crypto_rsa)

tests: tests_crypto_rsa
tests_crypto_rsa:

lint: lint_crypto_rsa
lint_crypto_rsa:
	lint -DLINT $(INCLUDES_crypto_rsa) $(SRC_crypto_rsa)>crypto/rsa/fluff

dclean: dclean_crypto_rsa
dclean_crypto_rsa:

clean: clean_crypto_rsa
clean_crypto_rsa:
	rm -f crypto/rsa/*.o crypto/rsa/*.d */*.o */*.d crypto/rsa/*.obj crypto/rsa/lib crypto/rsa/tags crypto/rsa/core crypto/rsa/.pure crypto/rsa/.nfs* crypto/rsa/*.old crypto/rsa/*.bak crypto/rsa/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_rsa) $(CPPFLAGS) -c -o $@ $<
