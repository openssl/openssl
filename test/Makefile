#
# test/Makefile
#

DIR=		test
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES) -I$(TOP)/fips
CFLAG=		-g
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
PERL=		perl
# KRB5 stuff
KRB5_INCLUDES=
LIBKRB5=
TEST=		fips_algvs.c igetest.c

PEX_LIBS=
EX_LIBS= #-lnsl -lsocket

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile maketests.com \
	tests.com testenc.com tx509.com trsa.com tcrl.com tsid.com treq.com \
	tpkcs7.com tpkcs7d.com tverify.com testgen.com testss.com testssl.com \
	testca.com VMSca-response.1 VMSca-response.2

DLIBCRYPTO= ../libcrypto.a
DLIBSSL= ../libssl.a
LIBCRYPTO= -L.. -lcrypto
LIBSSL= -L.. -lssl
LIBFIPS= -L.. -lfips

BNTEST=		bntest
ECTEST=		ectest
ECDSATEST=	ecdsatest
ECDHTEST=	ecdhtest
EXPTEST=	exptest
IDEATEST=	ideatest
SHATEST=	shatest
SHA1TEST=	sha1test
SHA256TEST=	sha256t
SHA512TEST=	sha512t
MDC2TEST=	mdc2test
RMDTEST=	rmdtest
MD2TEST=	md2test
MD4TEST=	md4test
MD5TEST=	md5test
HMACTEST=	hmactest
WPTEST=		wp_test
RC2TEST=	rc2test
RC4TEST=	rc4test
RC5TEST=	rc5test
BFTEST=		bftest
CASTTEST=	casttest
DESTEST=	destest
GOST2814789TEST=gost2814789t
RANDTEST=	randtest
DHTEST=		dhtest
DSATEST=	dsatest
METHTEST=	methtest
SSLTEST=	ssltest
RSATEST=	rsa_test
ENGINETEST=	enginetest
EVPTEST=	evp_test
IGETEST=	igetest
JPAKETEST=	jpaketest
SRPTEST=	srptest
V3NAMETEST=	v3nametest
FIPS_SHATEST=	fips_shatest
FIPS_DESTEST=	fips_desmovs
FIPS_RANDTEST=	fips_randtest
FIPS_AESTEST=	fips_aesavs
FIPS_GCMTEST=	fips_gcmtest
FIPS_HMACTEST=	fips_hmactest
FIPS_RSAVTEST=	fips_rsavtest
FIPS_RSASTEST=	fips_rsastest
FIPS_RSAGTEST=	fips_rsagtest
FIPS_DSATEST=	fips_dsatest
FIPS_DSSVS=	fips_dssvs
FIPS_RNGVS=	fips_rngvs
FIPS_DRBGVS=	fips_drbgvs
FIPS_DHVS=	fips_dhvs
FIPS_ECDHVS=	fips_ecdhvs
FIPS_ECDSAVS=	fips_ecdsavs
FIPS_TEST_SUITE=fips_test_suite
FIPS_CMACTEST=	fips_cmactest
FIPS_ALGVS=	fips_algvs
HEARTBEATTEST = heartbeat_test

TESTS=		alltests

EXE=	$(BNTEST)$(EXE_EXT) $(ECTEST)$(EXE_EXT)  $(ECDSATEST)$(EXE_EXT) $(ECDHTEST)$(EXE_EXT) $(IDEATEST)$(EXE_EXT) \
	$(MD2TEST)$(EXE_EXT)  $(MD4TEST)$(EXE_EXT) $(MD5TEST)$(EXE_EXT) $(HMACTEST)$(EXE_EXT) $(WPTEST)$(EXE_EXT) \
	$(RC2TEST)$(EXE_EXT) $(RC4TEST)$(EXE_EXT) $(RC5TEST)$(EXE_EXT) \
	$(DESTEST)$(EXE_EXT) $(SHATEST)$(EXE_EXT) $(SHA1TEST)$(EXE_EXT) $(SHA256TEST)$(EXE_EXT) $(SHA512TEST)$(EXE_EXT) \
	$(MDC2TEST)$(EXE_EXT) $(RMDTEST)$(EXE_EXT) \
	$(RANDTEST)$(EXE_EXT) $(DHTEST)$(EXE_EXT) $(ENGINETEST)$(EXE_EXT) \
	$(GOST2814789TEST)$(EXE_EXT) \
	$(BFTEST)$(EXE_EXT) $(CASTTEST)$(EXE_EXT) $(SSLTEST)$(EXE_EXT) \
	$(EXPTEST)$(EXE_EXT) $(DSATEST)$(EXE_EXT) $(RSATEST)$(EXE_EXT) \
	$(EVPTEST)$(EXE_EXT) $(IGETEST)$(EXE_EXT) $(JPAKETEST)$(EXE_EXT) $(SRPTEST)$(EXE_EXT) \
	$(V3NAMETEST)$(EXE_EXT) $(HEARTBEATTEST)$(EXE_EXT)

FIPSEXE=$(FIPS_SHATEST)$(EXE_EXT) $(FIPS_DESTEST)$(EXE_EXT) \
	$(FIPS_RANDTEST)$(EXE_EXT) $(FIPS_AESTEST)$(EXE_EXT) \
	$(FIPS_HMACTEST)$(EXE_EXT) $(FIPS_RSAVTEST)$(EXE_EXT) \
	$(FIPS_RSASTEST)$(EXE_EXT) $(FIPS_RSAGTEST)$(EXE_EXT) \
	$(FIPS_DSSVS)$(EXE_EXT) $(FIPS_DSATEST)$(EXE_EXT) \
	$(FIPS_RNGVS)$(EXE_EXT) $(FIPS_DRBGVS)$(EXE_EXT) \
	$(FIPS_DHVS)$(EXE_EXT)  $(FIPS_TEST_SUITE)$(EXE_EXT)  \
	$(FIPS_GCMTEST)$(EXE_EXT) $(FIPS_ECDSAVS)$(EXE_EXT) \
	$(FIPS_ECDHVS)$(EXE_EXT) $(FIPS_CMACTEST)$(EXE_EXT)

# $(METHTEST)$(EXE_EXT)

OBJ=	$(BNTEST).o $(ECTEST).o  $(ECDSATEST).o $(ECDHTEST).o $(IDEATEST).o \
	$(MD2TEST).o $(MD4TEST).o $(MD5TEST).o \
	$(HMACTEST).o $(WPTEST).o \
	$(RC2TEST).o $(RC4TEST).o $(RC5TEST).o \
	$(DESTEST).o $(SHATEST).o $(SHA1TEST).o $(SHA256TEST).o $(SHA512TEST).o \
	$(MDC2TEST).o $(RMDTEST).o \
	$(RANDTEST).o $(DHTEST).o $(ENGINETEST).o $(CASTTEST).o \
	$(BFTEST).o  $(SSLTEST).o  $(DSATEST).o  $(EXPTEST).o $(RSATEST).o \
	$(FIPS_SHATEST).o $(FIPS_DESTEST).o $(FIPS_RANDTEST).o \
	$(FIPS_AESTEST).o $(FIPS_HMACTEST).o $(FIPS_RSAVTEST).o \
	$(FIPS_RSASTEST).o $(FIPS_RSAGTEST).o $(FIPS_GCMTEST).o \
	$(FIPS_DSSVS).o $(FIPS_DSATEST).o $(FIPS_RNGVS).o $(FIPS_DRBGVS).o \
	$(FIPS_TEST_SUITE).o $(FIPS_DHVS).o $(FIPS_ECDSAVS).o \
	$(FIPS_ECDHVS).o $(FIPS_CMACTEST).o $(FIPS_ALGVS).o \
	$(EVPTEST).o $(IGETEST).o $(JPAKETEST).o $(V3NAMETEST).o \
	$(GOST2814789TEST).o $(HEARTBEATTEST).o
SRC=	$(BNTEST).c $(ECTEST).c  $(ECDSATEST).c $(ECDHTEST).c $(IDEATEST).c \
	$(MD2TEST).c  $(MD4TEST).c $(MD5TEST).c \
	$(HMACTEST).c $(WPTEST).c \
	$(RC2TEST).c $(RC4TEST).c $(RC5TEST).c \
	$(DESTEST).c $(SHATEST).c $(SHA1TEST).c $(MDC2TEST).c $(RMDTEST).c \
	$(RANDTEST).c $(DHTEST).c $(ENGINETEST).c $(CASTTEST).c \
	$(BFTEST).c  $(SSLTEST).c $(DSATEST).c   $(EXPTEST).c $(RSATEST).c \
	$(FIPS_SHATEST).c $(FIPS_DESTEST).c $(FIPS_RANDTEST).c \
	$(FIPS_AESTEST).c $(FIPS_HMACTEST).c $(FIPS_RSAVTEST).c \
	$(FIPS_RSASTEST).c $(FIPS_RSAGTEST).c $(FIPS_GCMTEST).c \
	$(FIPS_DSSVS).c $(FIPS_DSATEST).c $(FIPS_RNGVS).c $(FIPS_DRBGVS).c \
	$(FIPS_TEST_SUITE).c $(FIPS_DHVS).c $(FIPS_ECDSAVS).c \
	$(FIPS_ECDHVS).c $(FIPS_CMACTEST).c $(FIPS_ALGVS).c \
	$(EVPTEST).c $(IGETEST).c $(JPAKETEST).c $(V3NAMETEST).c \
	$(GOST2814789TEST).c $(HEARTBEATTEST).c

EXHEADER= 
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) TESTS=$(TESTS) all)

all:	exe

exe:	$(EXE) $(FIPSEXE) dummytest$(EXE_EXT)

fipsexe:	$(FIPSEXE)

fipsalgvs:	$(FIPS_ALGVS)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:

generate: $(SRC)
$(SRC):
	@sh $(TOP)/util/point.sh dummytest.c $@

errors:

install:

tags:
	ctags $(SRC)

tests:	exe apps $(TESTS)

apps:
	@(cd ..; $(MAKE) DIRS=apps all)

alltests: \
	test_des test_idea test_sha test_md4 test_md5 test_hmac \
	test_md2 test_mdc2 test_wp \
	test_rmd test_rc2 test_rc4 test_rc5 test_bf test_cast \
	test_rand test_bn test_ec test_ecdsa test_ecdh \
	test_enc test_x509 test_rsa test_crl test_sid \
	test_gen test_req test_pkcs7 test_verify test_dh test_dsa \
	test_ss test_ca test_engine test_evp test_ssl test_tsa test_ige \
	test_jpake test_srp test_cms test_v3name test_ocsp \
	test_gost2814789 test_heartbeat

test_evp: $(EVPTEST)$(EXE_EXT) evptests.txt
	../util/shlib_wrap.sh ./$(EVPTEST) evptests.txt

test_des: $(DESTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(DESTEST)

test_idea: $(IDEATEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(IDEATEST)

test_sha: $(SHATEST)$(EXE_EXT) $(SHA1TEST)$(EXE_EXT) $(SHA256TEST)$(EXE_EXT) $(SHA512TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(SHATEST)
	../util/shlib_wrap.sh ./$(SHA1TEST)
	../util/shlib_wrap.sh ./$(SHA256TEST)
	../util/shlib_wrap.sh ./$(SHA512TEST)

test_mdc2: $(MDC2TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(MDC2TEST)

test_md5: $(MD5TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(MD5TEST)

test_md4: $(MD4TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(MD4TEST)

test_hmac: $(HMACTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(HMACTEST)

test_wp: $(WPTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(WPTEST)

test_md2: $(MD2TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(MD2TEST)

test_rmd: $(RMDTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(RMDTEST)

test_bf: $(BFTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(BFTEST)

test_cast: $(CASTTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(CASTTEST)

test_rc2: $(RC2TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(RC2TEST)

test_rc4: $(RC4TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(RC4TEST)

test_rc5: $(RC5TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(RC5TEST)

test_rand: $(RANDTEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(RANDTEST)

test_gost2814789: $(GOST2814789TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(GOST2814789TEST)

test_enc: ../apps/openssl$(EXE_EXT) testenc
	@sh ./testenc

test_x509: ../apps/openssl$(EXE_EXT) tx509 testx509.pem v3-cert1.pem v3-cert2.pem
	echo test normal x509v1 certificate
	sh ./tx509 2>/dev/null
	echo test first x509v3 certificate
	sh ./tx509 v3-cert1.pem 2>/dev/null
	echo test second x509v3 certificate
	sh ./tx509 v3-cert2.pem 2>/dev/null

test_rsa: $(RSATEST)$(EXE_EXT) ../apps/openssl$(EXE_EXT) trsa testrsa.pem
	@sh ./trsa 2>/dev/null
	../util/shlib_wrap.sh ./$(RSATEST)

test_crl: ../apps/openssl$(EXE_EXT) tcrl testcrl.pem
	@sh ./tcrl 2>/dev/null

test_sid: ../apps/openssl$(EXE_EXT) tsid testsid.pem
	@sh ./tsid 2>/dev/null

test_req: ../apps/openssl$(EXE_EXT) treq testreq.pem testreq2.pem
	@sh ./treq 2>/dev/null
	@sh ./treq testreq2.pem 2>/dev/null

test_pkcs7: ../apps/openssl$(EXE_EXT) tpkcs7 tpkcs7d testp7.pem pkcs7-1.pem
	@sh ./tpkcs7 2>/dev/null
	@sh ./tpkcs7d 2>/dev/null

test_bn: $(BNTEST)$(EXE_EXT) $(EXPTEST)$(EXE_EXT) bctest
	@echo starting big number library test, could take a while...
	@../util/shlib_wrap.sh ./$(BNTEST) >tmp.bntest
	@echo quit >>tmp.bntest
	@echo "running bc"
	@<tmp.bntest sh -c "`sh ./bctest ignore`" | $(PERL) -e '$$i=0; while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $$1";} elsif (!/^0$$/) {die "\nFailed! bc: $$_";} else {print STDERR "."; $$i++;}} print STDERR "\n$$i tests passed\n"'
	@echo 'test a^b%c implementations'
	../util/shlib_wrap.sh ./$(EXPTEST)

test_ec: $(ECTEST)$(EXE_EXT)
	@echo 'test elliptic curves'
	../util/shlib_wrap.sh ./$(ECTEST)

test_ecdsa: $(ECDSATEST)$(EXE_EXT)
	@echo 'test ecdsa'
	../util/shlib_wrap.sh ./$(ECDSATEST)

test_ecdh: $(ECDHTEST)$(EXE_EXT)
	@echo 'test ecdh'
	../util/shlib_wrap.sh ./$(ECDHTEST)

test_verify: ../apps/openssl$(EXE_EXT)
	@echo "The following command should have some OK's and some failures"
	@echo "There are definitly a few expired certificates"
	../util/shlib_wrap.sh ../apps/openssl verify -CApath ../certs/demo ../certs/demo/*.pem

test_dh: $(DHTEST)$(EXE_EXT)
	@echo "Generate a set of DH parameters"
	../util/shlib_wrap.sh ./$(DHTEST)

test_dsa: $(DSATEST)$(EXE_EXT)
	@echo "Generate a set of DSA parameters"
	../util/shlib_wrap.sh ./$(DSATEST)
	../util/shlib_wrap.sh ./$(DSATEST) -app2_1

test_gen testreq.pem: ../apps/openssl$(EXE_EXT) testgen test.cnf
	@echo "Generate and verify a certificate request"
	@sh ./testgen

test_ss keyU.ss certU.ss certCA.ss certP1.ss keyP1.ss certP2.ss keyP2.ss \
		intP1.ss intP2.ss: testss CAss.cnf Uss.cnf P1ss.cnf P2ss.cnf \
                                   ../apps/openssl$(EXE_EXT)
	@echo "Generate and certify a test certificate"
	@sh ./testss
	@cat certCA.ss certU.ss > intP1.ss
	@cat certCA.ss certU.ss certP1.ss > intP2.ss

test_engine: $(ENGINETEST)$(EXE_EXT)
	@echo "Manipulate the ENGINE structures"
	../util/shlib_wrap.sh ./$(ENGINETEST)

test_ssl: keyU.ss certU.ss certCA.ss certP1.ss keyP1.ss certP2.ss keyP2.ss \
		intP1.ss intP2.ss $(SSLTEST)$(EXE_EXT) testssl testsslproxy \
		../apps/server2.pem serverinfo.pem
	@echo "test SSL protocol"
	../util/shlib_wrap.sh ./$(SSLTEST) -test_cipherlist
	@sh ./testssl keyU.ss certU.ss certCA.ss
	@sh ./testsslproxy keyP1.ss certP1.ss intP1.ss
	@sh ./testsslproxy keyP2.ss certP2.ss intP2.ss

test_ca: ../apps/openssl$(EXE_EXT) testca CAss.cnf Uss.cnf
	@if ../util/shlib_wrap.sh ../apps/openssl no-rsa; then \
	  echo "skipping CA.sh test -- requires RSA"; \
	else \
	  echo "Generate and certify a test certificate via the 'ca' program"; \
	  sh ./testca; \
	fi

test_tsa: ../apps/openssl$(EXE_EXT) testtsa CAtsa.cnf ../util/shlib_wrap.sh
	@if ../util/shlib_wrap.sh ../apps/openssl no-rsa; then \
	  echo "skipping testtsa test -- requires RSA"; \
	else \
	  sh ./testtsa; \
	fi

test_ige: $(IGETEST)$(EXE_EXT)
	@echo "Test IGE mode"
	../util/shlib_wrap.sh ./$(IGETEST)

test_jpake: $(JPAKETEST)$(EXE_EXT)
	@echo "Test JPAKE"
	../util/shlib_wrap.sh ./$(JPAKETEST)

test_cms: ../apps/openssl$(EXE_EXT) cms-test.pl smcont.txt
	@echo "CMS consistency test"
	$(PERL) cms-test.pl

test_srp: $(SRPTEST)$(EXE_EXT)
	@echo "Test SRP"
	../util/shlib_wrap.sh ./srptest

test_v3name: $(V3NAMETEST)$(EXE_EXT)
	@echo "Test X509v3_check_*"
	../util/shlib_wrap.sh ./$(V3NAMETEST)

test_ocsp: ../apps/openssl$(EXE_EXT) tocsp
	@echo "Test OCSP"
	@sh ./tocsp

test_heartbeat: $(HEARTBEATTEST)$(EXE_EXT)
	./$<

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f $(SRC) $(SHA256TEST).c $(SHA512TEST).c evptests.txt newkey.pem testkey.pem \
			testreq.pem

clean:
	rm -f .rnd tmp.bntest tmp.bctest *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE) $(FIPSEXE) *.ss *.srl log dummytest

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO) $(LIBKRB5)"; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

$(RSATEST)$(EXE_EXT): $(RSATEST).o $(DLIBCRYPTO)
	@target=$(RSATEST); $(BUILD_CMD)

$(BNTEST)$(EXE_EXT): $(BNTEST).o $(DLIBCRYPTO)
	@target=$(BNTEST); $(BUILD_CMD)

$(ECTEST)$(EXE_EXT): $(ECTEST).o $(DLIBCRYPTO)
	@target=$(ECTEST); $(BUILD_CMD)

$(EXPTEST)$(EXE_EXT): $(EXPTEST).o $(DLIBCRYPTO)
	@target=$(EXPTEST); $(BUILD_CMD)

$(IDEATEST)$(EXE_EXT): $(IDEATEST).o $(DLIBCRYPTO)
	@target=$(IDEATEST); $(BUILD_CMD)

$(MD2TEST)$(EXE_EXT): $(MD2TEST).o $(DLIBCRYPTO)
	@target=$(MD2TEST); $(BUILD_CMD)

$(SHATEST)$(EXE_EXT): $(SHATEST).o $(DLIBCRYPTO)
	@target=$(SHATEST); $(BUILD_CMD)

$(SHA1TEST)$(EXE_EXT): $(SHA1TEST).o $(DLIBCRYPTO)
	@target=$(SHA1TEST); $(BUILD_CMD)

$(SHA256TEST)$(EXE_EXT): $(SHA256TEST).o $(DLIBCRYPTO)
	@target=$(SHA256TEST); $(BUILD_CMD)

$(SHA512TEST)$(EXE_EXT): $(SHA512TEST).o $(DLIBCRYPTO)
	@target=$(SHA512TEST); $(BUILD_CMD)

FIPS_BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	if [ "$(FIPSCANLIB)" = "libfips" ]; then \
		LIBRARIES="-L$(TOP) -lfips"; \
	elif [ -n "$(FIPSCANLIB)" ]; then \
		FIPSLD_CC="$(CC)"; CC=$(TOP)/fips/fipsld; export CC FIPSLD_CC; \
		LIBRARIES="$${FIPSLIBDIR:-$(TOP)/fips/}fipscanister.o"; \
	else \
		LIBRARIES="$(LIBCRYPTO)"; \
	fi; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		CC="$${CC}" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

FIPS_CRYPTO_BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO) $(LIBKRB5)"; \
	if [ -z "$(SHARED_LIBS)" -a -n "$(FIPSCANLIB)" ] ; then \
		FIPSLD_CC="$(CC)"; CC=$(TOP)/fips/fipsld; export CC FIPSLD_CC; \
	fi; \
	[ "$(FIPSCANLIB)" = "libfips" ] && LIBRARIES="$$LIBRARIES -lfips"; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		CC="$${CC}" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

$(FIPS_SHATEST)$(EXE_EXT): $(FIPS_SHATEST).o $(DLIBCRYPTO)
	@target=$(FIPS_SHATEST); $(FIPS_BUILD_CMD)

$(FIPS_AESTEST)$(EXE_EXT): $(FIPS_AESTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_AESTEST); $(FIPS_BUILD_CMD)

$(FIPS_GCMTEST)$(EXE_EXT): $(FIPS_GCMTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_GCMTEST); $(FIPS_BUILD_CMD)

$(FIPS_DESTEST)$(EXE_EXT): $(FIPS_DESTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_DESTEST); $(FIPS_BUILD_CMD)

$(FIPS_HMACTEST)$(EXE_EXT): $(FIPS_HMACTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_HMACTEST); $(FIPS_BUILD_CMD)

$(FIPS_RANDTEST)$(EXE_EXT): $(FIPS_RANDTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RANDTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSAVTEST)$(EXE_EXT): $(FIPS_RSAVTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RSAVTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSASTEST)$(EXE_EXT): $(FIPS_RSASTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RSASTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSAGTEST)$(EXE_EXT): $(FIPS_RSAGTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RSAGTEST); $(FIPS_BUILD_CMD)

$(FIPS_DSATEST)$(EXE_EXT): $(FIPS_DSATEST).o $(DLIBCRYPTO)
	@target=$(FIPS_DSATEST); $(FIPS_BUILD_CMD)

$(FIPS_DSSVS)$(EXE_EXT): $(FIPS_DSSVS).o $(DLIBCRYPTO)
	@target=$(FIPS_DSSVS); $(FIPS_BUILD_CMD)

$(FIPS_DHVS)$(EXE_EXT): $(FIPS_DHVS).o $(DLIBCRYPTO)
	@target=$(FIPS_DHVS); $(FIPS_BUILD_CMD)

$(FIPS_ECDHVS)$(EXE_EXT): $(FIPS_ECDHVS).o $(DLIBCRYPTO)
	@target=$(FIPS_ECDHVS); $(FIPS_BUILD_CMD)

$(FIPS_ECDSAVS)$(EXE_EXT): $(FIPS_ECDSAVS).o $(DLIBCRYPTO)
	@target=$(FIPS_ECDSAVS); $(FIPS_BUILD_CMD)

$(FIPS_RNGVS)$(EXE_EXT): $(FIPS_RNGVS).o $(DLIBCRYPTO)
	@target=$(FIPS_RNGVS); $(FIPS_BUILD_CMD)

$(FIPS_DRBGVS)$(EXE_EXT): $(FIPS_DRBGVS).o $(DLIBCRYPTO)
	@target=$(FIPS_DRBGVS); $(FIPS_BUILD_CMD)

$(FIPS_TEST_SUITE)$(EXE_EXT): $(FIPS_TEST_SUITE).o $(DLIBCRYPTO)
	@target=$(FIPS_TEST_SUITE); $(FIPS_BUILD_CMD)

$(FIPS_CMACTEST)$(EXE_EXT): $(FIPS_CMACTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_CMACTEST); $(FIPS_BUILD_CMD)

$(FIPS_ALGVS)$(EXE_EXT): $(FIPS_ALGVS).o $(DLIBCRYPTO)
	@target=$(FIPS_ALGVS); $(FIPS_BUILD_CMD)

$(RMDTEST)$(EXE_EXT): $(RMDTEST).o $(DLIBCRYPTO)
	@target=$(RMDTEST); $(BUILD_CMD)

$(MDC2TEST)$(EXE_EXT): $(MDC2TEST).o $(DLIBCRYPTO)
	@target=$(MDC2TEST); $(BUILD_CMD)

$(MD4TEST)$(EXE_EXT): $(MD4TEST).o $(DLIBCRYPTO)
	@target=$(MD4TEST); $(BUILD_CMD)

$(MD5TEST)$(EXE_EXT): $(MD5TEST).o $(DLIBCRYPTO)
	@target=$(MD5TEST); $(BUILD_CMD)

$(HMACTEST)$(EXE_EXT): $(HMACTEST).o $(DLIBCRYPTO)
	@target=$(HMACTEST); $(BUILD_CMD)

$(WPTEST)$(EXE_EXT): $(WPTEST).o $(DLIBCRYPTO)
	@target=$(WPTEST); $(BUILD_CMD)

$(RC2TEST)$(EXE_EXT): $(RC2TEST).o $(DLIBCRYPTO)
	@target=$(RC2TEST); $(BUILD_CMD)

$(BFTEST)$(EXE_EXT): $(BFTEST).o $(DLIBCRYPTO)
	@target=$(BFTEST); $(BUILD_CMD)

$(CASTTEST)$(EXE_EXT): $(CASTTEST).o $(DLIBCRYPTO)
	@target=$(CASTTEST); $(BUILD_CMD)

$(RC4TEST)$(EXE_EXT): $(RC4TEST).o $(DLIBCRYPTO)
	@target=$(RC4TEST); $(BUILD_CMD)

$(RC5TEST)$(EXE_EXT): $(RC5TEST).o $(DLIBCRYPTO)
	@target=$(RC5TEST); $(BUILD_CMD)

$(DESTEST)$(EXE_EXT): $(DESTEST).o $(DLIBCRYPTO)
	@target=$(DESTEST); $(BUILD_CMD)

$(GOST2814789TEST)$(EXE_EXT): $(GOST2814789TEST).o $(DLIBCRYPTO)
	@target=$(GOST2814789TEST); $(BUILD_CMD)

$(RANDTEST)$(EXE_EXT): $(RANDTEST).o $(DLIBCRYPTO)
	@target=$(RANDTEST); $(BUILD_CMD)

$(DHTEST)$(EXE_EXT): $(DHTEST).o $(DLIBCRYPTO)
	@target=$(DHTEST); $(BUILD_CMD)

$(DSATEST)$(EXE_EXT): $(DSATEST).o $(DLIBCRYPTO)
	@target=$(DSATEST); $(BUILD_CMD)

$(METHTEST)$(EXE_EXT): $(METHTEST).o $(DLIBCRYPTO)
	@target=$(METHTEST); $(BUILD_CMD)

$(SSLTEST)$(EXE_EXT): $(SSLTEST).o $(DLIBSSL) $(DLIBCRYPTO)
	@target=$(SSLTEST); $(BUILD_CMD)

$(ENGINETEST)$(EXE_EXT): $(ENGINETEST).o $(DLIBCRYPTO)
	@target=$(ENGINETEST); $(BUILD_CMD)

$(EVPTEST)$(EXE_EXT): $(EVPTEST).o $(DLIBCRYPTO)
	@target=$(EVPTEST); $(BUILD_CMD)

$(ECDSATEST)$(EXE_EXT): $(ECDSATEST).o $(DLIBCRYPTO)
	@target=$(ECDSATEST); $(BUILD_CMD)

$(ECDHTEST)$(EXE_EXT): $(ECDHTEST).o $(DLIBCRYPTO)
	@target=$(ECDHTEST); $(BUILD_CMD)

$(IGETEST)$(EXE_EXT): $(IGETEST).o $(DLIBCRYPTO)
	@target=$(IGETEST); $(BUILD_CMD)

$(JPAKETEST)$(EXE_EXT): $(JPAKETEST).o $(DLIBCRYPTO)
	@target=$(JPAKETEST); $(BUILD_CMD)

$(SRPTEST)$(EXE_EXT): $(SRPTEST).o $(DLIBCRYPTO)
	@target=$(SRPTEST); $(BUILD_CMD)

$(V3NAMETEST)$(EXE_EXT): $(V3NAMETEST).o $(DLIBCRYPTO)
	@target=$(V3NAMETEST); $(BUILD_CMD)

$(HEARTBEATTEST)$(EXE_EXT): $(HEARTBEATTEST).o $(DLIBCRYPTO)
	@target=$(HEARTBEATTEST); $(BUILD_CMD)

#$(AESTEST).o: $(AESTEST).c
#	$(CC) -c $(CFLAGS) -DINTERMEDIATE_VALUE_KAT -DTRACE_KAT_MCT $(AESTEST).c

#$(AESTEST)$(EXE_EXT): $(AESTEST).o $(DLIBCRYPTO)
#	if [ "$(SHLIB_TARGET)" = "hpux-shared" -o "$(SHLIB_TARGET)" = "darwin-shared" ] ; then \
#	  $(CC) -o $(AESTEST)$(EXE_EXT) $(CFLAGS) $(AESTEST).o $(PEX_LIBS) $(DLIBCRYPTO) $(EX_LIBS) ; \
#	else \
#	  $(CC) -o $(AESTEST)$(EXE_EXT) $(CFLAGS) $(AESTEST).o $(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS) ; \
#	fi

dummytest$(EXE_EXT): dummytest.o $(DLIBCRYPTO)
	@target=dummytest; $(BUILD_CMD)

# DO NOT DELETE THIS LINE -- make depend depends on it.

bftest.o: ../e_os.h ../include/openssl/blowfish.h ../include/openssl/e_os2.h
bftest.o: ../include/openssl/opensslconf.h bftest.c
bntest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
bntest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
bntest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
bntest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
bntest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
bntest.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
bntest.o: ../include/openssl/evp.h ../include/openssl/lhash.h
bntest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
bntest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
bntest.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
bntest.o: ../include/openssl/rand.h ../include/openssl/rsa.h
bntest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
bntest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
bntest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h bntest.c
casttest.o: ../e_os.h ../include/openssl/cast.h ../include/openssl/e_os2.h
casttest.o: ../include/openssl/opensslconf.h casttest.c
destest.o: ../include/openssl/des.h ../include/openssl/des_old.h
destest.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
destest.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
destest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
destest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h destest.c
dhtest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
dhtest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
dhtest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
dhtest.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
dhtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dhtest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
dhtest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h dhtest.c
dsatest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
dsatest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
dsatest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsatest.o: ../include/openssl/err.h ../include/openssl/lhash.h
dsatest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsatest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
dsatest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
dsatest.o: ../include/openssl/symhacks.h dsatest.c
ecdhtest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecdhtest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
ecdhtest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecdhtest.o: ../include/openssl/ecdh.h ../include/openssl/err.h
ecdhtest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecdhtest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ecdhtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecdhtest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
ecdhtest.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecdhtest.o: ../include/openssl/symhacks.h ecdhtest.c
ecdsatest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ecdsatest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecdsatest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ecdsatest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ecdsatest.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ecdsatest.o: ../include/openssl/err.h ../include/openssl/evp.h
ecdsatest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecdsatest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ecdsatest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecdsatest.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ecdsatest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ecdsatest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ecdsatest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ecdsatest.o: ecdsatest.c
ectest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ectest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ectest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ectest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ectest.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ectest.o: ../include/openssl/err.h ../include/openssl/evp.h
ectest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ectest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ectest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ectest.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ectest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ectest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ectest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h ectest.c
enginetest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
enginetest.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
enginetest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
enginetest.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enginetest.o: ../include/openssl/engine.h ../include/openssl/err.h
enginetest.o: ../include/openssl/evp.h ../include/openssl/lhash.h
enginetest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
enginetest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enginetest.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
enginetest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
enginetest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
enginetest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
enginetest.o: enginetest.c
evp_test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
evp_test.o: ../include/openssl/buffer.h ../include/openssl/conf.h
evp_test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
evp_test.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
evp_test.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
evp_test.o: ../include/openssl/err.h ../include/openssl/evp.h
evp_test.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
evp_test.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
evp_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
evp_test.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
evp_test.o: ../include/openssl/sha.h ../include/openssl/stack.h
evp_test.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
evp_test.o: ../include/openssl/x509_vfy.h evp_test.c
exptest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
exptest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
exptest.o: ../include/openssl/err.h ../include/openssl/lhash.h
exptest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
exptest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
exptest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
exptest.o: ../include/openssl/symhacks.h exptest.c
fips_aesavs.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
fips_aesavs.o: ../include/openssl/bio.h ../include/openssl/bn.h
fips_aesavs.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
fips_aesavs.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_aesavs.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
fips_aesavs.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_aesavs.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_aesavs.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_aesavs.o: ../include/openssl/symhacks.h fips_aesavs.c
fips_algvs.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
fips_algvs.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_algvs.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
fips_algvs.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_algvs.o: fips_algvs.c
fips_cmactest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_cmactest.o: ../include/openssl/bn.h ../include/openssl/cmac.h
fips_cmactest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
fips_cmactest.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_cmactest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
fips_cmactest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_cmactest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_cmactest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_cmactest.o: ../include/openssl/symhacks.h fips_cmactest.c
fips_desmovs.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
fips_desmovs.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_desmovs.o: ../include/openssl/des.h ../include/openssl/des_old.h
fips_desmovs.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_desmovs.o: ../include/openssl/evp.h ../include/openssl/lhash.h
fips_desmovs.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
fips_desmovs.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_desmovs.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
fips_desmovs.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_desmovs.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_desmovs.o: fips_desmovs.c
fips_dhvs.o: ../include/openssl/opensslconf.h fips_dhvs.c
fips_drbgvs.o: ../include/openssl/opensslconf.h fips_drbgvs.c
fips_dsatest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
fips_dsatest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_dsatest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_dsatest.o: ../include/openssl/evp.h ../include/openssl/lhash.h
fips_dsatest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
fips_dsatest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_dsatest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
fips_dsatest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_dsatest.o: ../include/openssl/symhacks.h fips_dsatest.c
fips_dssvs.o: ../include/openssl/opensslconf.h fips_dssvs.c
fips_ecdhvs.o: ../include/openssl/opensslconf.h fips_ecdhvs.c
fips_ecdsavs.o: ../include/openssl/opensslconf.h fips_ecdsavs.c
fips_gcmtest.o: ../include/openssl/opensslconf.h fips_gcmtest.c
fips_hmactest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_hmactest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_hmactest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_hmactest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
fips_hmactest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
fips_hmactest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_hmactest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_hmactest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_hmactest.o: ../include/openssl/symhacks.h fips_hmactest.c
fips_randtest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
fips_randtest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
fips_randtest.o: ../include/openssl/err.h ../include/openssl/lhash.h
fips_randtest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_randtest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
fips_randtest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_randtest.o: ../include/openssl/symhacks.h fips_randtest.c
fips_rngvs.o: ../include/openssl/opensslconf.h fips_rngvs.c
fips_rsagtest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_rsagtest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_rsagtest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_rsagtest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
fips_rsagtest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
fips_rsagtest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_rsagtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_rsagtest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_rsagtest.o: ../include/openssl/symhacks.h fips_rsagtest.c
fips_rsastest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_rsastest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_rsastest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_rsastest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
fips_rsastest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
fips_rsastest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_rsastest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_rsastest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_rsastest.o: ../include/openssl/symhacks.h fips_rsastest.c
fips_rsavtest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_rsavtest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_rsavtest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_rsavtest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
fips_rsavtest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
fips_rsavtest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_rsavtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_rsavtest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_rsavtest.o: ../include/openssl/symhacks.h fips_rsavtest.c
fips_shatest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_shatest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_shatest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_shatest.o: ../include/openssl/evp.h ../include/openssl/lhash.h
fips_shatest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
fips_shatest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_shatest.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
fips_shatest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_shatest.o: fips_shatest.c
fips_test_suite.o: ../include/openssl/asn1.h ../include/openssl/bio.h
fips_test_suite.o: ../include/openssl/bn.h ../include/openssl/cmac.h
fips_test_suite.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
fips_test_suite.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_test_suite.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
fips_test_suite.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
fips_test_suite.o: ../include/openssl/opensslconf.h
fips_test_suite.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_test_suite.o: ../include/openssl/rand.h ../include/openssl/safestack.h
fips_test_suite.o: ../include/openssl/sha.h ../include/openssl/stack.h
fips_test_suite.o: ../include/openssl/symhacks.h fips_test_suite.c
gost2814789t.o: ../engines/ccgost/gost89.h ../include/openssl/asn1.h
gost2814789t.o: ../include/openssl/bio.h ../include/openssl/buffer.h
gost2814789t.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gost2814789t.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
gost2814789t.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
gost2814789t.o: ../include/openssl/engine.h ../include/openssl/err.h
gost2814789t.o: ../include/openssl/evp.h ../include/openssl/hmac.h
gost2814789t.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
gost2814789t.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
gost2814789t.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gost2814789t.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
gost2814789t.o: ../include/openssl/sha.h ../include/openssl/stack.h
gost2814789t.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
gost2814789t.o: ../include/openssl/x509_vfy.h gost2814789t.c
heartbeat_test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
heartbeat_test.o: ../include/openssl/buffer.h ../include/openssl/comp.h
heartbeat_test.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
heartbeat_test.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
heartbeat_test.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
heartbeat_test.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
heartbeat_test.o: ../include/openssl/evp.h ../include/openssl/hmac.h
heartbeat_test.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
heartbeat_test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
heartbeat_test.o: ../include/openssl/opensslconf.h
heartbeat_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
heartbeat_test.o: ../include/openssl/pem.h ../include/openssl/pem2.h
heartbeat_test.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
heartbeat_test.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
heartbeat_test.o: ../include/openssl/sha.h ../include/openssl/srtp.h
heartbeat_test.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
heartbeat_test.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
heartbeat_test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
heartbeat_test.o: ../include/openssl/tls1.h ../include/openssl/x509.h
heartbeat_test.o: ../include/openssl/x509_vfy.h ../ssl/ssl_locl.h
heartbeat_test.o: heartbeat_test.c
hmactest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
hmactest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
hmactest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
hmactest.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
hmactest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
hmactest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
hmactest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
hmactest.o: ../include/openssl/symhacks.h hmactest.c
ideatest.o: ../e_os.h ../include/openssl/e_os2.h ../include/openssl/idea.h
ideatest.o: ../include/openssl/opensslconf.h ideatest.c
igetest.o: ../include/openssl/aes.h ../include/openssl/crypto.h
igetest.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
igetest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
igetest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
igetest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h igetest.c
jpaketest.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
jpaketest.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
jpaketest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
jpaketest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
jpaketest.o: ../include/openssl/symhacks.h jpaketest.c
md2test.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
md2test.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
md2test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
md2test.o: ../include/openssl/safestack.h ../include/openssl/stack.h
md2test.o: ../include/openssl/symhacks.h md2test.c
md4test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
md4test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
md4test.o: ../include/openssl/evp.h ../include/openssl/md4.h
md4test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
md4test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
md4test.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
md4test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h md4test.c
md5test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
md5test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
md5test.o: ../include/openssl/evp.h ../include/openssl/md5.h
md5test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
md5test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
md5test.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
md5test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h md5test.c
mdc2test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
mdc2test.o: ../include/openssl/crypto.h ../include/openssl/des.h
mdc2test.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
mdc2test.o: ../include/openssl/evp.h ../include/openssl/mdc2.h
mdc2test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
mdc2test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mdc2test.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
mdc2test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
mdc2test.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h mdc2test.c
randtest.o: ../e_os.h ../include/openssl/e_os2.h
randtest.o: ../include/openssl/opensslconf.h ../include/openssl/ossl_typ.h
randtest.o: ../include/openssl/rand.h randtest.c
rc2test.o: ../e_os.h ../include/openssl/e_os2.h
rc2test.o: ../include/openssl/opensslconf.h ../include/openssl/rc2.h rc2test.c
rc4test.o: ../e_os.h ../include/openssl/e_os2.h
rc4test.o: ../include/openssl/opensslconf.h ../include/openssl/rc4.h
rc4test.o: ../include/openssl/sha.h rc4test.c
rc5test.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
rc5test.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
rc5test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rc5test.o: ../include/openssl/safestack.h ../include/openssl/stack.h
rc5test.o: ../include/openssl/symhacks.h rc5test.c
rmdtest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rmdtest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rmdtest.o: ../include/openssl/evp.h ../include/openssl/obj_mac.h
rmdtest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rmdtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rmdtest.o: ../include/openssl/ripemd.h ../include/openssl/safestack.h
rmdtest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h rmdtest.c
rsa_test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa_test.o: ../include/openssl/bn.h ../include/openssl/crypto.h
rsa_test.o: ../include/openssl/e_os2.h ../include/openssl/err.h
rsa_test.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
rsa_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa_test.o: ../include/openssl/rand.h ../include/openssl/rsa.h
rsa_test.o: ../include/openssl/safestack.h ../include/openssl/stack.h
rsa_test.o: ../include/openssl/symhacks.h rsa_test.c
sha1test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sha1test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
sha1test.o: ../include/openssl/evp.h ../include/openssl/obj_mac.h
sha1test.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
sha1test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sha1test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sha1test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h sha1test.c
shatest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
shatest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
shatest.o: ../include/openssl/evp.h ../include/openssl/obj_mac.h
shatest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
shatest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
shatest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
shatest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h shatest.c
ssltest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssltest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssltest.o: ../include/openssl/comp.h ../include/openssl/conf.h
ssltest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ssltest.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssltest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssltest.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssltest.o: ../include/openssl/engine.h ../include/openssl/err.h
ssltest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssltest.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssltest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssltest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssltest.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssltest.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssltest.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
ssltest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssltest.o: ../include/openssl/sha.h ../include/openssl/srp.h
ssltest.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssltest.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssltest.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssltest.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssltest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssltest.o: ../include/openssl/x509v3.h ssltest.c
v3nametest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
v3nametest.o: ../include/openssl/buffer.h ../include/openssl/conf.h
v3nametest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
v3nametest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
v3nametest.o: ../include/openssl/ecdsa.h ../include/openssl/evp.h
v3nametest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
v3nametest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
v3nametest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
v3nametest.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
v3nametest.o: ../include/openssl/sha.h ../include/openssl/stack.h
v3nametest.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
v3nametest.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
v3nametest.o: v3nametest.c
wp_test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
wp_test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
wp_test.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
wp_test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
wp_test.o: ../include/openssl/whrlpool.h wp_test.c
