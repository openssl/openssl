#
# OpenSSL/fips/dsa/Makefile
#

INCLUDES_fips_dsa=

CFLAGS_fips_dsa= $(INCLUDES_fips_dsa) $(CFLAG)

GENERAL_fips_dsa=fips/dsa/Makefile
TEST_fips_dsa=fips/dsa/fips_dsatest.c fips/dsa/fips_dssvs.c
APPS_fips_dsa=

LIB_fips_dsa=libcrypto.a
LIBSRC_fips_dsa= fips/dsa/fips_dsa_selftest.c \
	fips/dsa/fips_dsa_lib.c fips/dsa/fips_dsa_sign.c
LIBOBJ_fips_dsa= fips/dsa/fips_dsa_selftest.o \
	fips/dsa/fips_dsa_lib.o fips/dsa/fips_dsa_sign.o

SRC_fips_dsa= $(LIBSRC_fips_dsa)

EXHEADER_fips_dsa=
HEADER_fips_dsa=	$(EXHEADER_fips_dsa)

ALL_fips_dsa=    $(GENERAL_fips_dsa) $(SRC_fips_dsa) $(HEADER_fips_dsa)


all: all_fips_dsa
all_fips_dsa:	fips/dsa/lib

fips/dsa/lib:	$(LIBOBJ_fips_dsa)
	@echo $(LIBOBJ_fips_dsa) > fips/dsa/lib

files: files_fips_dsa
files_fips_dsa:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_dsa
links_fips_dsa:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_dsa)
	@$(PERL) util/mklink.pl test $(TEST_fips_dsa)
	@$(PERL) util/mklink.pl apps $(APPS_fips_dsa)

install: install_fips_dsa
install_fips_dsa:
	@headerlist="$(EXHEADER_fips_dsa)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_dsa
tags_fips_dsa:
	ctags $(SRC_fips_dsa)

tests: tests_fips_dsa
tests_fips_dsa:

Q_fips_dsa=../testvectors/dsa/req
A_fips_dsa=../testvectors/dsa/rsp

fips_test: fips_test_fips_dsa
fips_test_fips_dsa:
	-rm -rf $A
	mkdir $A
	if [ -f $(Q_fips_dsa)/PQGGen.req ]; then util/shlib_wrap.sh test/fips_dssvs pqg < $(Q_fips_dsa)/PQGGen.req > $(A_fips_dsa)/PQGGen.rsp; fi
	if [ -f $(Q_fips_dsa)/KeyPair.req ]; then util/shlib_wrap.sh test/fips_dssvs keypair < $(Q_fips_dsa)/KeyPair.req > $(A_fips_dsa)/KeyPair.rsp; fi
	if [ -f $(Q_fips_dsa)/SigGen.req ]; then util/shlib_wrap.sh test/fips_dssvs siggen < $(Q_fips_dsa)/SigGen.req > $(A_fips_dsa)/SigGen.rsp; fi
	if [ -f $(Q_fips_dsa)/SigVer.req ]; then util/shlib_wrap.sh test/fips_dssvs sigver < $Q/SigVer.req > $A/SigVer.rsp; fi

lint: lint_fips_dsa
lint_fips_dsa:
	lint -DLINT $(INCLUDES_fips_dsa) $(SRC_fips_dsa)>fips/dsa/fluff

dclean: dclean_fips_dsa
dclean_fips_dsa:

clean: clean_fips_dsa
clean_fips_dsa:
	rm -f fips/dsa/*.o fips/dsa/*.d fips/dsa/*.obj fips/dsa/lib fips/dsa/tags fips/dsa/core fips/dsa/.pure fips/dsa/.nfs* fips/dsa/*.old fips/dsa/*.bak fips/dsa/fluff

