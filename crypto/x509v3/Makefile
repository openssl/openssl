#
# OpenSSL/crypto/x509v3/Makefile
#


CFLAGS_crypto_x509v3= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_x509v3=crypto/x509v3/Makefile crypto/x509v3/README
TEST_crypto_x509v3=crypto/x509v3/v3nametest.c
APPS_crypto_x509v3=

LIB_crypto_x509v3=libcrypto.a
LIBSRC_crypto_x509v3=	crypto/x509v3/v3_bcons.c crypto/x509v3/v3_bitst.c crypto/x509v3/v3_conf.c crypto/x509v3/v3_extku.c crypto/x509v3/v3_ia5.c crypto/x509v3/v3_lib.c \
crypto/x509v3/v3_prn.c crypto/x509v3/v3_utl.c crypto/x509v3/v3err.c crypto/x509v3/v3_genn.c crypto/x509v3/v3_alt.c crypto/x509v3/v3_skey.c crypto/x509v3/v3_akey.c crypto/x509v3/v3_pku.c \
crypto/x509v3/v3_int.c crypto/x509v3/v3_enum.c crypto/x509v3/v3_sxnet.c crypto/x509v3/v3_cpols.c crypto/x509v3/v3_crld.c crypto/x509v3/v3_purp.c crypto/x509v3/v3_info.c \
crypto/x509v3/v3_ocsp.c crypto/x509v3/v3_akeya.c crypto/x509v3/v3_pmaps.c crypto/x509v3/v3_pcons.c crypto/x509v3/v3_ncons.c crypto/x509v3/v3_pcia.c crypto/x509v3/v3_pci.c \
crypto/x509v3/pcy_cache.c crypto/x509v3/pcy_node.c crypto/x509v3/pcy_data.c crypto/x509v3/pcy_map.c crypto/x509v3/pcy_tree.c crypto/x509v3/pcy_lib.c \
crypto/x509v3/v3_asid.c crypto/x509v3/v3_addr.c crypto/x509v3/v3_scts.c
LIBOBJ_crypto_x509v3= crypto/x509v3/v3_bcons.o crypto/x509v3/v3_bitst.o crypto/x509v3/v3_conf.o crypto/x509v3/v3_extku.o crypto/x509v3/v3_ia5.o crypto/x509v3/v3_lib.o \
crypto/x509v3/v3_prn.o crypto/x509v3/v3_utl.o crypto/x509v3/v3err.o crypto/x509v3/v3_genn.o crypto/x509v3/v3_alt.o crypto/x509v3/v3_skey.o crypto/x509v3/v3_akey.o crypto/x509v3/v3_pku.o \
crypto/x509v3/v3_int.o crypto/x509v3/v3_enum.o crypto/x509v3/v3_sxnet.o crypto/x509v3/v3_cpols.o crypto/x509v3/v3_crld.o crypto/x509v3/v3_purp.o crypto/x509v3/v3_info.o \
crypto/x509v3/v3_ocsp.o crypto/x509v3/v3_akeya.o crypto/x509v3/v3_pmaps.o crypto/x509v3/v3_pcons.o crypto/x509v3/v3_ncons.o crypto/x509v3/v3_pcia.o crypto/x509v3/v3_pci.o \
crypto/x509v3/pcy_cache.o crypto/x509v3/pcy_node.o crypto/x509v3/pcy_data.o crypto/x509v3/pcy_map.o crypto/x509v3/pcy_tree.o crypto/x509v3/pcy_lib.o \
crypto/x509v3/v3_asid.o crypto/x509v3/v3_addr.o crypto/x509v3/v3_scts.o

SRC_crypto_x509v3= $(LIBSRC_crypto_x509v3)

EXHEADER_crypto_x509v3= crypto/x509v3/x509v3.h
HEADER_crypto_x509v3=	$(EXHEADER_crypto_x509v3) crypto/x509v3/pcy_int.h

ALL_crypto_x509v3=    $(GENERAL_crypto_x509v3) $(SRC_crypto_x509v3) $(HEADER_crypto_x509v3)


all: all_crypto_x509v3
all_crypto_x509v3:	$(LIBOBJ_crypto_x509v3)


files: files_crypto_x509v3
files_crypto_x509v3:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_x509v3
links_crypto_x509v3:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_x509v3)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_x509v3)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_x509v3)

install: install_crypto_x509v3
install_crypto_x509v3:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_x509v3)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_x509v3
tags_crypto_x509v3:
	ctags $(SRC_crypto_x509v3)

tests: tests_crypto_x509v3
tests_crypto_x509v3:

lint: lint_crypto_x509v3
lint_crypto_x509v3:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_x509v3)>crypto/x509v3/fluff

dclean: dclean_crypto_x509v3
dclean_crypto_x509v3:

clean: clean_crypto_x509v3
clean_crypto_x509v3:
	rm -f crypto/x509v3/*.o crypto/x509v3/*.d crypto/x509v3/*.obj crypto/x509v3/lib crypto/x509v3/tags crypto/x509v3/core crypto/x509v3/.pure crypto/x509v3/.nfs* crypto/x509v3/*.old crypto/x509v3/*.bak crypto/x509v3/fluff

