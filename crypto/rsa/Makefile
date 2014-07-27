#
# OpenSSL/crypto/rsa/Makefile
#

INCLUDES_crypto_rsa= -I.. -I$(TOP_crypto_rsa) -I../../include

CFLAGS_crypto_rsa= $(INCLUDES_crypto_rsa) $(CFLAG)

GENERAL_crypto_rsa=Makefile
TEST_crypto_rsa=rsa_test.c
APPS_crypto_rsa=

LIB_crypto_rsa=$(TOP_crypto_rsa)/libcrypto.a
LIBSRC_crypto_rsa= rsa_eay.c rsa_gen.c rsa_lib.c rsa_sign.c rsa_saos.c rsa_err.c \
	rsa_pk1.c rsa_ssl.c rsa_none.c rsa_oaep.c rsa_chk.c rsa_null.c \
	rsa_pss.c rsa_x931.c rsa_asn1.c rsa_depr.c rsa_ameth.c rsa_prn.c \
	rsa_pmeth.c rsa_crpt.c rsa_x931g.c
LIBOBJ_crypto_rsa= rsa_eay.o rsa_gen.o rsa_lib.o rsa_sign.o rsa_saos.o rsa_err.o \
	rsa_pk1.o rsa_ssl.o rsa_none.o rsa_oaep.o rsa_chk.o rsa_null.o \
	rsa_pss.o rsa_x931.o rsa_asn1.o rsa_depr.o rsa_ameth.o rsa_prn.o \
	rsa_pmeth.o rsa_crpt.o rsa_x931g.o

SRC_crypto_rsa= $(LIBSRC_crypto_rsa)

EXHEADER_crypto_rsa= rsa.h
HEADER_crypto_rsa=	$(EXHEADER_crypto_rsa)

ALL_crypto_rsa=    $(GENERAL_crypto_rsa) $(SRC_crypto_rsa) $(HEADER_crypto_rsa)


all: all_crypto_rsa
all_crypto_rsa:	lib

lib:	$(LIBOBJ_crypto_rsa)
	$(ARX) $(LIB_crypto_rsa) $(LIBOBJ_crypto_rsa)
	$(RANLIB) $(LIB_crypto_rsa) || echo Never mind.
	@touch lib

files: files_crypto_rsa
files_crypto_rsa:
	$(PERL) $(TOP_crypto_rsa)/util/files.pl TOP=$(TOP_crypto_rsa) Makefile >> $(TOP_crypto_rsa)/MINFO

links: links_crypto_rsa
links_crypto_rsa:
	@$(PERL) $(TOP_crypto_rsa)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_rsa)
	@$(PERL) $(TOP_crypto_rsa)/util/mklink.pl ../../test $(TEST_crypto_rsa)
	@$(PERL) $(TOP_crypto_rsa)/util/mklink.pl ../../apps $(APPS_crypto_rsa)

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
	lint -DLINT $(INCLUDES_crypto_rsa) $(SRC_crypto_rsa)>fluff

dclean: dclean_crypto_rsa
dclean_crypto_rsa:

clean: clean_crypto_rsa
clean_crypto_rsa:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_rsa) $(CPPFLAGS) -c -o $@ $<
