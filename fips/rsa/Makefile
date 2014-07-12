#
# OpenSSL/fips/rsa/Makefile
#

DIR_fips_rsa=	rsa
INCLUDES_fips_rsa=

CFLAGS_fips_rsa= $(INCLUDES_fips_rsa) $(CFLAG)

GENERAL_fips_rsa=Makefile
TEST_fips_rsa= fips_rsavtest.c fips_rsastest.c fips_rsagtest.c
APPS_fips_rsa=

LIB_fips_rsa=$(TOP_fips_rsa)/libcrypto.a
LIBSRC_fips_rsa= fips_rsa_selftest.c fips_rsa_sign.c fips_rsa_lib.c
LIBOBJ_fips_rsa= fips_rsa_selftest.o fips_rsa_sign.o fips_rsa_lib.o

SRC_fips_rsa= $(LIBSRC_fips_rsa)

EXHEADER_fips_rsa=
HEADER_fips_rsa=	$(EXHEADER_fips_rsa)

ALL_fips_rsa=    $(GENERAL_fips_rsa) $(SRC_fips_rsa) $(HEADER_fips_rsa)

top: top_fips_rsa
top_fips_rsa:
	(cd $(TOP_fips_rsa); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_rsa) sub_all)

all: all_fips_rsa
all_fips_rsa:	lib

lib:	$(LIBOBJ_fips_rsa)
	@echo $(LIBOBJ_fips_rsa) > lib

files: files_fips_rsa
files_fips_rsa:
	$(PERL) $(TOP_fips_rsa)/util/files.pl TOP=$(TOP_fips_rsa) Makefile >> $(TOP_fips_rsa)/MINFO

links: links_fips_rsa
links_fips_rsa:
	@$(PERL) $(TOP_fips_rsa)/util/mklink.pl $(TOP_fips_rsa)/include/openssl $(EXHEADER_fips_rsa)
	@$(PERL) $(TOP_fips_rsa)/util/mklink.pl $(TOP_fips_rsa)/test $(TEST_fips_rsa)
	@$(PERL) $(TOP_fips_rsa)/util/mklink.pl $(TOP_fips_rsa)/apps $(APPS_fips_rsa)

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
	if [ -f $(Q_fips_rsa)/SigGen15.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsastest < $(Q_fips_rsa)/SigGen15.req  > $(A_fips_rsa)/SigGen15.rsp; fi
	if [ -f $(Q_fips_rsa)/SigVer15.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsavtest < $(Q_fips_rsa)/SigVer15.req > $(A_fips_rsa)/SigVer15.rsp; fi
	if [ -f $(Q_fips_rsa)/SigGenPSS.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsastest -saltlen 0 < $(Q_fips_rsa)/SigGenPSS.req > $(A_fips_rsa)/SigGenPSS.rsp; fi
	if [ -f $(Q_fips_rsa)/SigVerPSS.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsavtest -saltlen 0 < $(Q_fips_rsa)/SigVerPSS.req > $(A_fips_rsa)/SigVerPSS.rsp; fi
	if [ -f $(Q_fips_rsa)/SigGenRSA.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsastest -x931 < $(Q_fips_rsa)/SigGenRSA.req > $(A_fips_rsa)/SigGenRSA.rsp; fi
	if [ -f $(Q_fips_rsa)/SigVerRSA.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsavtest -x931 < $(Q_fips_rsa)/SigVerRSA.req > $(A_fips_rsa)/SigVerRSA.rsp; fi
	if [ -f $(Q62)/SigGenPSS.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsastest -saltlen 62 < $(Q62)/SigGenPSS.req >$(A62)/SigGenPSS.rsp; fi
	if [ -f $(Q62)/SigVerPSS.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsavtest -saltlen 62 <$(Q62)/SigVerPSS.req >$(A62)/SigVerPSS.rsp; fi
	if [ -f $(Q_fips_rsa)/KeyGenRSA.req ]; then $(TOP_fips_rsa)/util/shlib_wrap.sh $(TOP_fips_rsa)/test/fips_rsagtest < $(Q_fips_rsa)/KeyGenRSA.req > $(A_fips_rsa)/KeyGenRSA.rsp; fi

lint: lint_fips_rsa
lint_fips_rsa:
	lint -DLINT $(INCLUDES_fips_rsa) $(SRC_fips_rsa)>fluff

dclean: dclean_fips_rsa
dclean_fips_rsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_rsa
clean_fips_rsa:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_rsa) $(CPPFLAGS) -c -o $@ $<
