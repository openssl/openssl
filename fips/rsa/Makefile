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

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

Q=../testvectors/rsa/req
A=../testvectors/rsa/rsp
Q62=../testvectors/rsa_salt_62/req
A62=../testvectors/rsa_salt_62/rsp

fips_test:
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

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
