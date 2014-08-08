#
# crypto/ecdsa/Makefile
#

INCLUDES_crypto_ecdsa= -Icrypto -I. -Iinclude

CFLAGS_crypto_ecdsa= $(INCLUDES_crypto_ecdsa) $(CFLAG)

GENERAL_crypto_ecdsa=crypto/ecdsa/Makefile
TEST_crypto_ecdsa=crypto/ecdsa/ecdsatest.c
APPS_crypto_ecdsa=

LIB_crypto_ecdsa=libcrypto.a
LIBSRC_crypto_ecdsa=	crypto/ecdsa/ecs_lib.c crypto/ecdsa/ecs_asn1.c crypto/ecdsa/ecs_ossl.c crypto/ecdsa/ecs_sign.c crypto/ecdsa/ecs_vrf.c crypto/ecdsa/ecs_err.c

LIBOBJ_crypto_ecdsa=	crypto/ecdsa/ecs_lib.o crypto/ecdsa/ecs_asn1.o crypto/ecdsa/ecs_ossl.o crypto/ecdsa/ecs_sign.o crypto/ecdsa/ecs_vrf.o crypto/ecdsa/ecs_err.o

SRC_crypto_ecdsa= $(LIBSRC_crypto_ecdsa)

EXHEADER_crypto_ecdsa= crypto/ecdsa/ecdsa.h
HEADER_crypto_ecdsa=	crypto/ecdsa/ecs_locl.h $(EXHEADER_crypto_ecdsa)

ALL_crypto_ecdsa=    $(GENERAL_crypto_ecdsa) $(SRC_crypto_ecdsa) $(HEADER_crypto_ecdsa)


all: all_crypto_ecdsa
all_crypto_ecdsa:	crypto/ecdsa/lib

crypto/ecdsa/lib:	$(LIBOBJ_crypto_ecdsa)
	$(ARX) $(LIB_crypto_ecdsa) $(LIBOBJ_crypto_ecdsa)
	$(RANLIB) $(LIB_crypto_ecdsa) || echo Never mind.
	@touch crypto/ecdsa/lib

files: files_crypto_ecdsa
files_crypto_ecdsa:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ecdsa
links_crypto_ecdsa:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ecdsa)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ecdsa)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ecdsa)

install: install_crypto_ecdsa
install_crypto_ecdsa:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ecdsa)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ecdsa
tags_crypto_ecdsa:
	ctags $(SRC_crypto_ecdsa)

tests: tests_crypto_ecdsa
tests_crypto_ecdsa:

lint: lint_crypto_ecdsa
lint_crypto_ecdsa:
	lint -DLINT $(INCLUDES_crypto_ecdsa) $(SRC_crypto_ecdsa)>crypto/ecdsa/fluff

dclean: dclean_crypto_ecdsa
dclean_crypto_ecdsa:

clean: clean_crypto_ecdsa
clean_crypto_ecdsa:
	rm -f crypto/ecdsa/*.o crypto/ecdsa/*.d */*.o */*.d crypto/ecdsa/*.obj crypto/ecdsa/lib crypto/ecdsa/tags crypto/ecdsa/core crypto/ecdsa/.pure crypto/ecdsa/.nfs* crypto/ecdsa/*.old crypto/ecdsa/*.bak crypto/ecdsa/fluff

