#
# OpenSSL/crypto/pkcs12/Makefile
#

INCLUDES_crypto_pkcs12= -Icrypto -I. -Iinclude

CFLAGS_crypto_pkcs12= $(INCLUDES_crypto_pkcs12) $(CFLAG)

GENERAL_crypto_pkcs12=crypto/pkcs12/Makefile
TEST_crypto_pkcs12=
APPS_crypto_pkcs12=

LIB_crypto_pkcs12=libcrypto.a
LIBSRC_crypto_pkcs12= crypto/pkcs12/p12_add.c crypto/pkcs12/p12_asn.c crypto/pkcs12/p12_attr.c crypto/pkcs12/p12_crpt.c crypto/pkcs12/p12_crt.c crypto/pkcs12/p12_decr.c \
	crypto/pkcs12/p12_init.c crypto/pkcs12/p12_key.c crypto/pkcs12/p12_kiss.c crypto/pkcs12/p12_mutl.c\
	crypto/pkcs12/p12_utl.c crypto/pkcs12/p12_npas.c crypto/pkcs12/pk12err.c crypto/pkcs12/p12_p8d.c crypto/pkcs12/p12_p8e.c
LIBOBJ_crypto_pkcs12= crypto/pkcs12/p12_add.o crypto/pkcs12/p12_asn.o crypto/pkcs12/p12_attr.o crypto/pkcs12/p12_crpt.o crypto/pkcs12/p12_crt.o crypto/pkcs12/p12_decr.o \
	crypto/pkcs12/p12_init.o crypto/pkcs12/p12_key.o crypto/pkcs12/p12_kiss.o crypto/pkcs12/p12_mutl.o\
	crypto/pkcs12/p12_utl.o crypto/pkcs12/p12_npas.o crypto/pkcs12/pk12err.o crypto/pkcs12/p12_p8d.o crypto/pkcs12/p12_p8e.o

SRC_crypto_pkcs12= $(LIBSRC_crypto_pkcs12)

EXHEADER_crypto_pkcs12=  crypto/pkcs12/pkcs12.h
HEADER_crypto_pkcs12=	$(EXHEADER_crypto_pkcs12)

ALL_crypto_pkcs12=    $(GENERAL_crypto_pkcs12) $(SRC_crypto_pkcs12) $(HEADER_crypto_pkcs12)


test: test_crypto_pkcs12
test_crypto_pkcs12:

all: all_crypto_pkcs12
all_crypto_pkcs12:	crypto/pkcs12/lib

crypto/pkcs12/lib:	$(LIBOBJ_crypto_pkcs12)
	$(ARX) $(LIB_crypto_pkcs12) $(LIBOBJ_crypto_pkcs12)
	$(RANLIB) $(LIB_crypto_pkcs12) || echo Never mind.
	@touch crypto/pkcs12/lib

files: files_crypto_pkcs12
files_crypto_pkcs12:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_pkcs12
links_crypto_pkcs12:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_pkcs12)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_pkcs12)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_pkcs12)

install: install_crypto_pkcs12
install_crypto_pkcs12:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_pkcs12)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pkcs12
tags_crypto_pkcs12:
	ctags $(SRC_crypto_pkcs12)

tests: tests_crypto_pkcs12
tests_crypto_pkcs12:

lint: lint_crypto_pkcs12
lint_crypto_pkcs12:
	lint -DLINT $(INCLUDES_crypto_pkcs12) $(SRC_crypto_pkcs12)>crypto/pkcs12/fluff

dclean: dclean_crypto_pkcs12
dclean_crypto_pkcs12:

clean: clean_crypto_pkcs12
clean_crypto_pkcs12:
	rm -f crypto/pkcs12/*.o crypto/pkcs12/*.d crypto/pkcs12/*.obj crypto/pkcs12/lib crypto/pkcs12/tags crypto/pkcs12/core crypto/pkcs12/.pure crypto/pkcs12/.nfs* crypto/pkcs12/*.old crypto/pkcs12/*.bak crypto/pkcs12/fluff

