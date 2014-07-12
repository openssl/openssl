#
# OpenSSL/fips/dsa/Makefile
#

DIR_fips_dsa=	dsa
INCLUDES_fips_dsa=

CFLAGS_fips_dsa= $(INCLUDES_fips_dsa) $(CFLAG)

GENERAL_fips_dsa=Makefile
TEST_fips_dsa=fips_dsatest.c fips_dssvs.c
APPS_fips_dsa=

LIB_fips_dsa=$(TOP_fips_dsa)/libcrypto.a
LIBSRC_fips_dsa= fips_dsa_selftest.c \
	fips_dsa_lib.c fips_dsa_sign.c
LIBOBJ_fips_dsa= fips_dsa_selftest.o \
	fips_dsa_lib.o fips_dsa_sign.o

SRC_fips_dsa= $(LIBSRC_fips_dsa)

EXHEADER_fips_dsa=
HEADER_fips_dsa=	$(EXHEADER_fips_dsa)

ALL_fips_dsa=    $(GENERAL_fips_dsa) $(SRC_fips_dsa) $(HEADER_fips_dsa)

top: top_fips_dsa
top_fips_dsa:
	(cd $(TOP_fips_dsa); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_dsa) sub_all)

all: all_fips_dsa
all_fips_dsa:	lib

lib: lib_fips_dsa
lib_fips_dsa:	$(LIBOBJ_fips_dsa)
	@echo $(LIBOBJ_fips_dsa) > lib

files: files_fips_dsa
files_fips_dsa:
	$(PERL) $(TOP_fips_dsa)/util/files.pl TOP=$(TOP_fips_dsa) Makefile >> $(TOP_fips_dsa)/MINFO

links: links_fips_dsa
links_fips_dsa:
	@$(PERL) $(TOP_fips_dsa)/util/mklink.pl $(TOP_fips_dsa)/include/openssl $(EXHEADER_fips_dsa)
	@$(PERL) $(TOP_fips_dsa)/util/mklink.pl $(TOP_fips_dsa)/test $(TEST_fips_dsa)
	@$(PERL) $(TOP_fips_dsa)/util/mklink.pl $(TOP_fips_dsa)/apps $(APPS_fips_dsa)

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
	if [ -f $(Q_fips_dsa)/PQGGen.req ]; then $(TOP_fips_dsa)/util/shlib_wrap.sh $(TOP_fips_dsa)/test/fips_dssvs pqg < $(Q_fips_dsa)/PQGGen.req > $(A_fips_dsa)/PQGGen.rsp; fi
	if [ -f $(Q_fips_dsa)/KeyPair.req ]; then $(TOP_fips_dsa)/util/shlib_wrap.sh $(TOP_fips_dsa)/test/fips_dssvs keypair < $(Q_fips_dsa)/KeyPair.req > $(A_fips_dsa)/KeyPair.rsp; fi
	if [ -f $(Q_fips_dsa)/SigGen.req ]; then $(TOP_fips_dsa)/util/shlib_wrap.sh $(TOP_fips_dsa)/test/fips_dssvs siggen < $(Q_fips_dsa)/SigGen.req > $(A_fips_dsa)/SigGen.rsp; fi
	if [ -f $(Q_fips_dsa)/SigVer.req ]; then $(TOP_fips_dsa)/util/shlib_wrap.sh $(TOP_fips_dsa)/test/fips_dssvs sigver < $Q/SigVer.req > $A/SigVer.rsp; fi

lint: lint_fips_dsa
lint_fips_dsa:
	lint -DLINT $(INCLUDES_fips_dsa) $(SRC_fips_dsa)>fluff

dclean: dclean_fips_dsa
dclean_fips_dsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_dsa
clean_fips_dsa:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_dsa) $(CPPFLAGS) -c -o $@ $<
