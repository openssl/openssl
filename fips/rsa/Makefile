#
# OpenSSL/fips/rsa/Makefile
#

INCLUDES_fips_rsa=

CFLAGS_fips_rsa= $(INCLUDES_fips_rsa) $(CFLAG)

GENERAL_fips_rsa=fips/rsa/Makefile
TEST_fips_rsa= fips/rsa/fips_rsavtest.c fips/rsa/fips_rsastest.c fips/rsa/fips_rsagtest.c
APPS_fips_rsa=

LIB_fips_rsa=libcrypto.a
LIBSRC_fips_rsa= fips/rsa/fips_rsa_selftest.c fips/rsa/fips_rsa_sign.c fips/rsa/fips_rsa_lib.c
LIBOBJ_fips_rsa= fips/rsa/fips_rsa_selftest.o fips/rsa/fips_rsa_sign.o fips/rsa/fips_rsa_lib.o

SRC_fips_rsa= $(LIBSRC_fips_rsa)

EXHEADER_fips_rsa=
HEADER_fips_rsa=	$(EXHEADER_fips_rsa)

ALL_fips_rsa=    $(GENERAL_fips_rsa) $(SRC_fips_rsa) $(HEADER_fips_rsa)


all: all_fips_rsa
all_fips_rsa:	fips/rsa/lib

fips/rsa/lib:	$(LIBOBJ_fips_rsa)
	@echo $(LIBOBJ_fips_rsa) > fips/rsa/lib

files: files_fips_rsa
files_fips_rsa:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_rsa
links_fips_rsa:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_rsa)
	@$(PERL) util/mklink.pl test $(TEST_fips_rsa)
	@$(PERL) util/mklink.pl apps $(APPS_fips_rsa)

install: install_fips_rsa
install_fips_rsa:
	@headerlist="$(EXHEADER_fips_rsa)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_rsa
tags_fips_rsa:
	ctags $(SRC_fips_rsa)

tests: tests_fips_rsa
tests_fips_rsa:

Q_fips_rsa=../testvectors/rsa/req
A_fips_rsa=../testvectors/rsa/rsp
Q62=../testvectors/rsa_salt_62/req
A62=../testvectors/rsa_salt_62/rsp

fips_test: fips_test_fips_rsa
fips_test_fips_rsa:
	-rm -rf $(A_fips_rsa) $(A62)
	mkdir $(A_fips_rsa) $(A62)
	if [ -f $(Q_fips_rsa)/SigGen15.req ]; then util/shlib_wrap.sh test/fips_rsastest < $(Q_fips_rsa)/SigGen15.req  > $(A_fips_rsa)/SigGen15.rsp; fi
	if [ -f $(Q_fips_rsa)/SigVer15.req ]; then util/shlib_wrap.sh test/fips_rsavtest < $(Q_fips_rsa)/SigVer15.req > $(A_fips_rsa)/SigVer15.rsp; fi
	if [ -f $(Q_fips_rsa)/SigGenPSS.req ]; then util/shlib_wrap.sh test/fips_rsastest -saltlen 0 < $(Q_fips_rsa)/SigGenPSS.req > $(A_fips_rsa)/SigGenPSS.rsp; fi
	if [ -f $(Q_fips_rsa)/SigVerPSS.req ]; then util/shlib_wrap.sh test/fips_rsavtest -saltlen 0 < $(Q_fips_rsa)/SigVerPSS.req > $(A_fips_rsa)/SigVerPSS.rsp; fi
	if [ -f $(Q_fips_rsa)/SigGenRSA.req ]; then util/shlib_wrap.sh test/fips_rsastest -x931 < $(Q_fips_rsa)/SigGenRSA.req > $(A_fips_rsa)/SigGenRSA.rsp; fi
	if [ -f $(Q_fips_rsa)/SigVerRSA.req ]; then util/shlib_wrap.sh test/fips_rsavtest -x931 < $(Q_fips_rsa)/SigVerRSA.req > $(A_fips_rsa)/SigVerRSA.rsp; fi
	if [ -f $(Q62)/SigGenPSS.req ]; then util/shlib_wrap.sh test/fips_rsastest -saltlen 62 < $(Q62)/SigGenPSS.req >$(A62)/SigGenPSS.rsp; fi
	if [ -f $(Q62)/SigVerPSS.req ]; then util/shlib_wrap.sh test/fips_rsavtest -saltlen 62 <$(Q62)/SigVerPSS.req >$(A62)/SigVerPSS.rsp; fi
	if [ -f $(Q_fips_rsa)/KeyGenRSA.req ]; then util/shlib_wrap.sh test/fips_rsagtest < $(Q_fips_rsa)/KeyGenRSA.req > $(A_fips_rsa)/KeyGenRSA.rsp; fi

lint: lint_fips_rsa
lint_fips_rsa:
	lint -DLINT $(INCLUDES_fips_rsa) $(SRC_fips_rsa)>fips/rsa/fluff

dclean: dclean_fips_rsa
dclean_fips_rsa:

clean: clean_fips_rsa
clean_fips_rsa:
	rm -f fips/rsa/*.o fips/rsa/*.d fips/rsa/*.obj fips/rsa/lib fips/rsa/tags fips/rsa/core fips/rsa/.pure fips/rsa/.nfs* fips/rsa/*.old fips/rsa/*.bak fips/rsa/fluff

.c.o:
	$(CC) $(CFLAGS_fips_rsa) $(CPPFLAGS) -c -o $@ $<
