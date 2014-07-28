#
# OpenSSL/crypto/dsa/Makefile
#

DIR_crypto_dsa=	dsa
INCLUDES_crypto_dsa= -I.. -I$(TOP_crypto_dsa) -I../../include

CFLAGS_crypto_dsa= $(INCLUDES_crypto_dsa) $(CFLAG)

GENERAL_crypto_dsa=Makefile
TEST_crypto_dsa=dsatest.c
APPS_crypto_dsa=

LIB_crypto_dsa=$(TOP_crypto_dsa)/libcrypto.a
LIBSRC_crypto_dsa= dsa_gen.c dsa_key.c dsa_lib.c dsa_asn1.c dsa_vrf.c dsa_sign.c \
	dsa_err.c dsa_ossl.c dsa_depr.c dsa_ameth.c dsa_pmeth.c dsa_prn.c
LIBOBJ_crypto_dsa= dsa_gen.o dsa_key.o dsa_lib.o dsa_asn1.o dsa_vrf.o dsa_sign.o \
	dsa_err.o dsa_ossl.o dsa_depr.o dsa_ameth.o dsa_pmeth.o dsa_prn.o

SRC_crypto_dsa= $(LIBSRC_crypto_dsa)

EXHEADER_crypto_dsa= dsa.h
HEADER_crypto_dsa=	dsa_locl.h $(EXHEADER_crypto_dsa)

ALL_crypto_dsa=    $(GENERAL_crypto_dsa) $(SRC_crypto_dsa) $(HEADER_crypto_dsa)

top: top_crypto_dsa
top_crypto_dsa:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_dsa) sub_all)

all: all_crypto_dsa
all_crypto_dsa:	lib

lib:	$(LIBOBJ_crypto_dsa)
	$(ARX) $(LIB_crypto_dsa) $(LIBOBJ_crypto_dsa)
	$(RANLIB) $(LIB_crypto_dsa) || echo Never mind.
	@touch lib

files: files_crypto_dsa
files_crypto_dsa:
	$(PERL) $(TOP_crypto_dsa)/util/files.pl TOP=$(TOP_crypto_dsa) Makefile >> $(TOP_crypto_dsa)/MINFO

links: links_crypto_dsa
links_crypto_dsa:
	@$(PERL) $(TOP_crypto_dsa)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_dsa)
	@$(PERL) $(TOP_crypto_dsa)/util/mklink.pl ../../test $(TEST_crypto_dsa)
	@$(PERL) $(TOP_crypto_dsa)/util/mklink.pl ../../apps $(APPS_crypto_dsa)

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
	lint -DLINT $(INCLUDES_crypto_dsa) $(SRC_crypto_dsa)>fluff

dclean: dclean_crypto_dsa
dclean_crypto_dsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_dsa
clean_crypto_dsa:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_dsa) $(CPPFLAGS) -c -o $@ $<
