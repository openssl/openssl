#
# OpenSSL/fips/rsa/Makefile
#

DIR=	rsa
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_rsavtest.c fips_rsastest.c fips_rsagtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_rsa_selftest.c fips_rsa_sign.c fips_rsa_lib.c
LIBOBJ= fips_rsa_selftest.o fips_rsa_sign.o fips_rsa_lib.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_rsa
top_fips_rsa:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_rsa
all_fips_rsa:	lib

lib: lib_fips_rsa
lib_fips_rsa:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_rsa
files_fips_rsa:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_rsa
links_fips_rsa:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_rsa
install_fips_rsa:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_rsa
tags_fips_rsa:
	ctags $(SRC)

tests: tests_fips_rsa
tests_fips_rsa:

Q=../testvectors/rsa/req
A=../testvectors/rsa/rsp
Q62=../testvectors/rsa_salt_62/req
A62=../testvectors/rsa_salt_62/rsp

fips_test: fips_test_fips_rsa
fips_test_fips_rsa:
	-rm -rf $(A) $(A62)
	mkdir $(A) $(A62)
	if [ -f $(Q)/SigGen15.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsastest < $(Q)/SigGen15.req  > $(A)/SigGen15.rsp; fi
	if [ -f $(Q)/SigVer15.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsavtest < $(Q)/SigVer15.req > $(A)/SigVer15.rsp; fi
	if [ -f $(Q)/SigGenPSS.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsastest -saltlen 0 < $(Q)/SigGenPSS.req > $(A)/SigGenPSS.rsp; fi
	if [ -f $(Q)/SigVerPSS.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsavtest -saltlen 0 < $(Q)/SigVerPSS.req > $(A)/SigVerPSS.rsp; fi
	if [ -f $(Q)/SigGenRSA.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsastest -x931 < $(Q)/SigGenRSA.req > $(A)/SigGenRSA.rsp; fi
	if [ -f $(Q)/SigVerRSA.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsavtest -x931 < $(Q)/SigVerRSA.req > $(A)/SigVerRSA.rsp; fi
	if [ -f $(Q62)/SigGenPSS.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsastest -saltlen 62 < $(Q62)/SigGenPSS.req >$(A62)/SigGenPSS.rsp; fi
	if [ -f $(Q62)/SigVerPSS.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsavtest -saltlen 62 <$(Q62)/SigVerPSS.req >$(A62)/SigVerPSS.rsp; fi
	if [ -f $(Q)/KeyGenRSA.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rsagtest < $(Q)/KeyGenRSA.req > $(A)/KeyGenRSA.rsp; fi

lint: lint_fips_rsa
lint_fips_rsa:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_rsa
dclean_fips_rsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_rsa
clean_fips_rsa:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
