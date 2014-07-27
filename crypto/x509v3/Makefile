#
# OpenSSL/crypto/x509v3/Makefile
#

INCLUDES_crypto_x509v3= -I.. -I$(TOP_crypto_x509v3) -I../../include

CFLAGS_crypto_x509v3= $(INCLUDES_crypto_x509v3) $(CFLAG)

GENERAL_crypto_x509v3=Makefile README
TEST_crypto_x509v3=v3nametest.c
APPS_crypto_x509v3=

LIB_crypto_x509v3=$(TOP_crypto_x509v3)/libcrypto.a
LIBSRC_crypto_x509v3=	v3_bcons.c v3_bitst.c v3_conf.c v3_extku.c v3_ia5.c v3_lib.c \
v3_prn.c v3_utl.c v3err.c v3_genn.c v3_alt.c v3_skey.c v3_akey.c v3_pku.c \
v3_int.c v3_enum.c v3_sxnet.c v3_cpols.c v3_crld.c v3_purp.c v3_info.c \
v3_ocsp.c v3_akeya.c v3_pmaps.c v3_pcons.c v3_ncons.c v3_pcia.c v3_pci.c \
pcy_cache.c pcy_node.c pcy_data.c pcy_map.c pcy_tree.c pcy_lib.c \
v3_asid.c v3_addr.c v3_scts.c
LIBOBJ_crypto_x509v3= v3_bcons.o v3_bitst.o v3_conf.o v3_extku.o v3_ia5.o v3_lib.o \
v3_prn.o v3_utl.o v3err.o v3_genn.o v3_alt.o v3_skey.o v3_akey.o v3_pku.o \
v3_int.o v3_enum.o v3_sxnet.o v3_cpols.o v3_crld.o v3_purp.o v3_info.o \
v3_ocsp.o v3_akeya.o v3_pmaps.o v3_pcons.o v3_ncons.o v3_pcia.o v3_pci.o \
pcy_cache.o pcy_node.o pcy_data.o pcy_map.o pcy_tree.o pcy_lib.o \
v3_asid.o v3_addr.o v3_scts.o

SRC_crypto_x509v3= $(LIBSRC_crypto_x509v3)

EXHEADER_crypto_x509v3= x509v3.h
HEADER_crypto_x509v3=	$(EXHEADER_crypto_x509v3) pcy_int.h

ALL_crypto_x509v3=    $(GENERAL_crypto_x509v3) $(SRC_crypto_x509v3) $(HEADER_crypto_x509v3)


all: all_crypto_x509v3
all_crypto_x509v3:	lib

lib:	$(LIBOBJ_crypto_x509v3)
	$(ARX) $(LIB_crypto_x509v3) $(LIBOBJ_crypto_x509v3)
	$(RANLIB) $(LIB_crypto_x509v3) || echo Never mind.
	@touch lib

files: files_crypto_x509v3
files_crypto_x509v3:
	$(PERL) $(TOP_crypto_x509v3)/util/files.pl TOP=$(TOP_crypto_x509v3) Makefile >> $(TOP_crypto_x509v3)/MINFO

links: links_crypto_x509v3
links_crypto_x509v3:
	@$(PERL) $(TOP_crypto_x509v3)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_x509v3)
	@$(PERL) $(TOP_crypto_x509v3)/util/mklink.pl ../../test $(TEST_crypto_x509v3)
	@$(PERL) $(TOP_crypto_x509v3)/util/mklink.pl ../../apps $(APPS_crypto_x509v3)

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
	lint -DLINT $(INCLUDES_crypto_x509v3) $(SRC_crypto_x509v3)>fluff

dclean: dclean_crypto_x509v3
dclean_crypto_x509v3:

clean: clean_crypto_x509v3
clean_crypto_x509v3:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_x509v3) $(CPPFLAGS) -c -o $@ $<
