#
# test/Makefile
#

DIR_test=		test
INCLUDES_test=	-I$(TOP_test) -I../include $(KRB5_INCLUDES) -I$(TOP_test)/fips
# KRB5 stuff
TEST_test=		fips_algvs.c igetest.c


CFLAGS_test= $(INCLUDES_test) $(CFLAG)

GENERAL_test=Makefile maketests.com \
	tests.com testenc.com tx509.com trsa.com tcrl.com tsid.com treq.com \
	tpkcs7.com tpkcs7d.com tverify.com testgen.com testss.com testssl.com \
	testca.com VMSca-response.1 VMSca-response.2

DLIBCRYPTO_test= ../libcrypto.a
DLIBSSL_test= ../libssl.a
LIBCRYPTO_test= -L.. -lcrypto
LIBSSL_test= -L.. -lssl
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
P5_CRPT2_TEST=	p5_crpt2_test
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
HEARTBEATTEST=  heartbeat_test
CONSTTIMETEST=  constant_time_test

TESTS_test=		alltests

EXE_test=	$(BNTEST)$(EXE_EXT) $(ECTEST)$(EXE_EXT)  $(ECDSATEST)$(EXE_EXT) $(ECDHTEST)$(EXE_EXT) $(IDEATEST)$(EXE_EXT) \
	$(MD2TEST)$(EXE_EXT)  $(MD4TEST)$(EXE_EXT) $(MD5TEST)$(EXE_EXT) $(HMACTEST)$(EXE_EXT) $(WPTEST)$(EXE_EXT) \
	$(RC2TEST)$(EXE_EXT) $(RC4TEST)$(EXE_EXT) $(RC5TEST)$(EXE_EXT) \
	$(DESTEST)$(EXE_EXT) $(SHATEST)$(EXE_EXT) $(SHA1TEST)$(EXE_EXT) $(SHA256TEST)$(EXE_EXT) $(SHA512TEST)$(EXE_EXT) \
	$(MDC2TEST)$(EXE_EXT) $(RMDTEST)$(EXE_EXT) \
	$(RANDTEST)$(EXE_EXT) $(DHTEST)$(EXE_EXT) $(ENGINETEST)$(EXE_EXT) \
	$(GOST2814789TEST)$(EXE_EXT) \
	$(BFTEST)$(EXE_EXT) $(CASTTEST)$(EXE_EXT) $(SSLTEST)$(EXE_EXT) \
	$(EXPTEST)$(EXE_EXT) $(DSATEST)$(EXE_EXT) $(RSATEST)$(EXE_EXT) \
	$(EVPTEST)$(EXE_EXT) $(IGETEST)$(EXE_EXT) $(JPAKETEST)$(EXE_EXT) $(SRPTEST)$(EXE_EXT) \
	$(V3NAMETEST)$(EXE_EXT) $(HEARTBEATTEST)$(EXE_EXT) $(P5_CRPT2_TEST)$(EXE_EXT) \
	$(CONSTTIMETEST)$(EXE_EXT)

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

OBJ_test=	$(BNTEST).o $(ECTEST).o  $(ECDSATEST).o $(ECDHTEST).o $(IDEATEST).o \
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
	$(GOST2814789TEST).o $(HEARTBEATTEST).o $(P5_CRPT2_TEST).o \
	$(CONSTTIMETEST).o testutil.o

SRC_test=	$(BNTEST).c $(ECTEST).c  $(ECDSATEST).c $(ECDHTEST).c $(IDEATEST).c \
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
	$(GOST2814789TEST).c $(HEARTBEATTEST).c $(P5_CRPT2_TEST).c \
	$(CONSTTIMETEST).c testutil.c

EXHEADER_test= 
HEADER_test=	testutil.h $(EXHEADER_test)

ALL_test=    $(GENERAL_test) $(SRC_test) $(HEADER_test)

top: top_test
top_test:
	(cd ..; $(MAKE) DIRS=$(DIR_test) TESTS=$(TESTS_test) all)

all: all_test
all_test:	exe

exe: exe_test
exe_test:	$(EXE_test) $(FIPSEXE) dummytest$(EXE_EXT)

fipsexe:	$(FIPSEXE)

fipsalgvs:	$(FIPS_ALGVS)

files: files_test
files_test:
	$(PERL) $(TOP_test)/util/files.pl TOP=$(TOP_test) Makefile >> $(TOP_test)/MINFO

links: links_test
links_test:

generate: $(SRC_test)
$(SRC_test):
	@sh $(TOP_test)/util/point.sh dummytest.c $@

errors: errors_test
errors_test:

install: install_test
install_test:

tags: tags_test
tags_test:
	ctags $(SRC_test)

tests: tests_test
tests_test:	exe apps $(TESTS_test)

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
	test_gost2814789 test_heartbeat test_p5_crpt2 \
	test_constant_time

test_evp: $(EVPTEST)$(EXE_EXT) evptests.txt
	../util/shlib_wrap.sh ./$(EVPTEST) evptests.txt

test_p5_crpt2: $(P5_CRPT2_TEST)$(EXE_EXT)
	../util/shlib_wrap.sh ./$(P5_CRPT2_TEST)

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
	OPENSSL_ENGINES=../engines/ccgost ../util/shlib_wrap.sh ./$(GOST2814789TEST)

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
	@<tmp.bntest sh -c "`sh ./bctest ignore`" | $(PERL) -e '$$i=0; while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $$1";} elsif (!/^0\r?$$/) {die "\nFailed! bc: $$_";} else {print STDERR "."; $$i++;}} print STDERR "\n$$i tests passed\n"'
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
	../util/shlib_wrap.sh ./$(HEARTBEATTEST)

test_constant_time: $(CONSTTIMETEST)$(EXE_EXT)
	@echo "Test constant time utilites"
	../util/shlib_wrap.sh ./$(CONSTTIMETEST)

lint: lint_test
lint_test:
	lint -DLINT $(INCLUDES_test) $(SRC_test)>fluff

dclean: dclean_test
dclean_test:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f $(SRC_test) $(SHA256TEST).c $(SHA512TEST).c evptests.txt newkey.pem testkey.pem \
			testreq.pem

clean: clean_test
clean_test:
	rm -f .rnd tmp.bntest tmp.bctest *.o *.d *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE_test) $(FIPSEXE) *.ss *.srl log dummytest

$(DLIBSSL_test):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO_test):
	(cd ..; $(MAKE) DIRS=crypto all)

BUILD_CMD_test=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL_test) $(LIBCRYPTO_test) $(LIBKRB5)"; \
	cat $(TOP_test)/configure.mk $(TOP_test)/Makefile.shared | $(MAKE) -f - \
		APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o $$testutil" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

BUILD_CMD_STATIC=shlib_target=; \
	LIBRARIES="$(DLIBSSL_test) $(DLIBCRYPTO_test) $(LIBKRB5)"; \
	cat $(TOP_test)/configure.mk $(TOP_test)/Makefile.shared | $(MAKE) -f - \
		APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o $$testutil" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

$(RSATEST)$(EXE_EXT): $(RSATEST).o $(DLIBCRYPTO_test)
	@target=$(RSATEST); $(BUILD_CMD_test)

$(BNTEST)$(EXE_EXT): $(BNTEST).o $(DLIBCRYPTO_test)
	@target=$(BNTEST); $(BUILD_CMD_test)

$(ECTEST)$(EXE_EXT): $(ECTEST).o $(DLIBCRYPTO_test)
	@target=$(ECTEST); $(BUILD_CMD_test)

$(EXPTEST)$(EXE_EXT): $(EXPTEST).o $(DLIBCRYPTO_test)
	@target=$(EXPTEST); $(BUILD_CMD_test)

$(IDEATEST)$(EXE_EXT): $(IDEATEST).o $(DLIBCRYPTO_test)
	@target=$(IDEATEST); $(BUILD_CMD_test)

$(MD2TEST)$(EXE_EXT): $(MD2TEST).o $(DLIBCRYPTO_test)
	@target=$(MD2TEST); $(BUILD_CMD_test)

$(SHATEST)$(EXE_EXT): $(SHATEST).o $(DLIBCRYPTO_test)
	@target=$(SHATEST); $(BUILD_CMD_test)

$(SHA1TEST)$(EXE_EXT): $(SHA1TEST).o $(DLIBCRYPTO_test)
	@target=$(SHA1TEST); $(BUILD_CMD_test)

$(SHA256TEST)$(EXE_EXT): $(SHA256TEST).o $(DLIBCRYPTO_test)
	@target=$(SHA256TEST); $(BUILD_CMD_test)

$(SHA512TEST)$(EXE_EXT): $(SHA512TEST).o $(DLIBCRYPTO_test)
	@target=$(SHA512TEST); $(BUILD_CMD_test)

FIPS_BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	if [ "$(FIPSCANLIB)" = "libfips" ]; then \
		LIBRARIES="-L$(TOP_test) -lfips"; \
	elif [ -n "$(FIPSCANLIB)" ]; then \
		FIPSLD_CC="$(CC)"; CC=$(TOP_test)/fips/fipsld; export CC FIPSLD_CC; \
		LIBRARIES="$${FIPSLIBDIR:-$(TOP_test)/fips/}fipscanister.o"; \
	else \
		LIBRARIES="$(LIBCRYPTO_test)"; \
	fi; \
	cat $(TOP_test)/configure.mk $(TOP_test)/Makefile.shared | $(MAKE) -f - \
		CC="$(CC)" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

FIPS_CRYPTO_BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL_test) $(LIBCRYPTO_test) $(LIBKRB5)"; \
	if [ -z "$(SHARED_LIBS)" -a -n "$(FIPSCANLIB)" ] ; then \
		FIPSLD_CC="$(CC)"; CC=$(TOP_test)/fips/fipsld; export CC FIPSLD_CC; \
	fi; \
	[ "$(FIPSCANLIB)" = "libfips" ] && LIBRARIES="$$LIBRARIES -lfips"; \
	cat $(TOP_test)/configure.mk $(TOP_test)/Makefile.shared | $(MAKE) -f - \
		CC="$(CC)" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

$(FIPS_SHATEST)$(EXE_EXT): $(FIPS_SHATEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_SHATEST); $(FIPS_BUILD_CMD)

$(FIPS_AESTEST)$(EXE_EXT): $(FIPS_AESTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_AESTEST); $(FIPS_BUILD_CMD)

$(FIPS_GCMTEST)$(EXE_EXT): $(FIPS_GCMTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_GCMTEST); $(FIPS_BUILD_CMD)

$(FIPS_DESTEST)$(EXE_EXT): $(FIPS_DESTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_DESTEST); $(FIPS_BUILD_CMD)

$(FIPS_HMACTEST)$(EXE_EXT): $(FIPS_HMACTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_HMACTEST); $(FIPS_BUILD_CMD)

$(FIPS_RANDTEST)$(EXE_EXT): $(FIPS_RANDTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_RANDTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSAVTEST)$(EXE_EXT): $(FIPS_RSAVTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_RSAVTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSASTEST)$(EXE_EXT): $(FIPS_RSASTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_RSASTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSAGTEST)$(EXE_EXT): $(FIPS_RSAGTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_RSAGTEST); $(FIPS_BUILD_CMD)

$(FIPS_DSATEST)$(EXE_EXT): $(FIPS_DSATEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_DSATEST); $(FIPS_BUILD_CMD)

$(FIPS_DSSVS)$(EXE_EXT): $(FIPS_DSSVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_DSSVS); $(FIPS_BUILD_CMD)

$(FIPS_DHVS)$(EXE_EXT): $(FIPS_DHVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_DHVS); $(FIPS_BUILD_CMD)

$(FIPS_ECDHVS)$(EXE_EXT): $(FIPS_ECDHVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_ECDHVS); $(FIPS_BUILD_CMD)

$(FIPS_ECDSAVS)$(EXE_EXT): $(FIPS_ECDSAVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_ECDSAVS); $(FIPS_BUILD_CMD)

$(FIPS_RNGVS)$(EXE_EXT): $(FIPS_RNGVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_RNGVS); $(FIPS_BUILD_CMD)

$(FIPS_DRBGVS)$(EXE_EXT): $(FIPS_DRBGVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_DRBGVS); $(FIPS_BUILD_CMD)

$(FIPS_TEST_SUITE)$(EXE_EXT): $(FIPS_TEST_SUITE).o $(DLIBCRYPTO_test)
	@target=$(FIPS_TEST_SUITE); $(FIPS_BUILD_CMD)

$(FIPS_CMACTEST)$(EXE_EXT): $(FIPS_CMACTEST).o $(DLIBCRYPTO_test)
	@target=$(FIPS_CMACTEST); $(FIPS_BUILD_CMD)

$(FIPS_ALGVS)$(EXE_EXT): $(FIPS_ALGVS).o $(DLIBCRYPTO_test)
	@target=$(FIPS_ALGVS); $(FIPS_BUILD_CMD)

$(RMDTEST)$(EXE_EXT): $(RMDTEST).o $(DLIBCRYPTO_test)
	@target=$(RMDTEST); $(BUILD_CMD_test)

$(MDC2TEST)$(EXE_EXT): $(MDC2TEST).o $(DLIBCRYPTO_test)
	@target=$(MDC2TEST); $(BUILD_CMD_test)

$(MD4TEST)$(EXE_EXT): $(MD4TEST).o $(DLIBCRYPTO_test)
	@target=$(MD4TEST); $(BUILD_CMD_test)

$(MD5TEST)$(EXE_EXT): $(MD5TEST).o $(DLIBCRYPTO_test)
	@target=$(MD5TEST); $(BUILD_CMD_test)

$(HMACTEST)$(EXE_EXT): $(HMACTEST).o $(DLIBCRYPTO_test)
	@target=$(HMACTEST); $(BUILD_CMD_test)

$(WPTEST)$(EXE_EXT): $(WPTEST).o $(DLIBCRYPTO_test)
	@target=$(WPTEST); $(BUILD_CMD_test)

$(RC2TEST)$(EXE_EXT): $(RC2TEST).o $(DLIBCRYPTO_test)
	@target=$(RC2TEST); $(BUILD_CMD_test)

$(BFTEST)$(EXE_EXT): $(BFTEST).o $(DLIBCRYPTO_test)
	@target=$(BFTEST); $(BUILD_CMD_test)

$(CASTTEST)$(EXE_EXT): $(CASTTEST).o $(DLIBCRYPTO_test)
	@target=$(CASTTEST); $(BUILD_CMD_test)

$(RC4TEST)$(EXE_EXT): $(RC4TEST).o $(DLIBCRYPTO_test)
	@target=$(RC4TEST); $(BUILD_CMD_test)

$(RC5TEST)$(EXE_EXT): $(RC5TEST).o $(DLIBCRYPTO_test)
	@target=$(RC5TEST); $(BUILD_CMD_test)

$(DESTEST)$(EXE_EXT): $(DESTEST).o $(DLIBCRYPTO_test)
	@target=$(DESTEST); $(BUILD_CMD_test)

$(GOST2814789TEST)$(EXE_EXT): $(GOST2814789TEST).o $(DLIBCRYPTO_test)
	@target=$(GOST2814789TEST); $(BUILD_CMD_test)

$(RANDTEST)$(EXE_EXT): $(RANDTEST).o $(DLIBCRYPTO_test)
	@target=$(RANDTEST); $(BUILD_CMD_test)

$(DHTEST)$(EXE_EXT): $(DHTEST).o $(DLIBCRYPTO_test)
	@target=$(DHTEST); $(BUILD_CMD_test)

$(DSATEST)$(EXE_EXT): $(DSATEST).o $(DLIBCRYPTO_test)
	@target=$(DSATEST); $(BUILD_CMD_test)

$(METHTEST)$(EXE_EXT): $(METHTEST).o $(DLIBCRYPTO_test)
	@target=$(METHTEST); $(BUILD_CMD_test)

$(SSLTEST)$(EXE_EXT): $(SSLTEST).o $(DLIBSSL_test) $(DLIBCRYPTO_test)
	@target=$(SSLTEST); $(BUILD_CMD_test)

$(ENGINETEST)$(EXE_EXT): $(ENGINETEST).o $(DLIBCRYPTO_test)
	@target=$(ENGINETEST); $(BUILD_CMD_test)

$(EVPTEST)$(EXE_EXT): $(EVPTEST).o $(DLIBCRYPTO_test)
	@target=$(EVPTEST); $(BUILD_CMD_test)

$(P5_CRPT2_TEST)$(EXE_EXT): $(P5_CRPT2_TEST).o $(DLIBCRYPTO_test)
	@target=$(P5_CRPT2_TEST); $(BUILD_CMD_test)

$(ECDSATEST)$(EXE_EXT): $(ECDSATEST).o $(DLIBCRYPTO_test)
	@target=$(ECDSATEST); $(BUILD_CMD_test)

$(ECDHTEST)$(EXE_EXT): $(ECDHTEST).o $(DLIBCRYPTO_test)
	@target=$(ECDHTEST); $(BUILD_CMD_test)

$(IGETEST)$(EXE_EXT): $(IGETEST).o $(DLIBCRYPTO_test)
	@target=$(IGETEST); $(BUILD_CMD_test)

$(JPAKETEST)$(EXE_EXT): $(JPAKETEST).o $(DLIBCRYPTO_test)
	@target=$(JPAKETEST); $(BUILD_CMD_test)

$(SRPTEST)$(EXE_EXT): $(SRPTEST).o $(DLIBCRYPTO_test)
	@target=$(SRPTEST); $(BUILD_CMD_test)

$(V3NAMETEST)$(EXE_EXT): $(V3NAMETEST).o $(DLIBCRYPTO_test)
	@target=$(V3NAMETEST); $(BUILD_CMD_test)

$(HEARTBEATTEST)$(EXE_EXT): $(HEARTBEATTEST).o $(DLIBCRYPTO_test) testutil.o
	@target=$(HEARTBEATTEST) testutil=testutil.o; $(BUILD_CMD_STATIC)

$(CONSTTIMETEST)$(EXE_EXT): $(CONSTTIMETEST).o
	@target=$(CONSTTIMETEST) $(BUILD_CMD_test)

#$(AESTEST).o: $(AESTEST).c
#	$(CC) -c $(CFLAGS_test) -DINTERMEDIATE_VALUE_KAT -DTRACE_KAT_MCT $(AESTEST).c

#$(AESTEST)$(EXE_EXT): $(AESTEST).o $(DLIBCRYPTO_test)
#	if [ "$(SHLIB_TARGET)" = "hpux-shared" -o "$(SHLIB_TARGET)" = "darwin-shared" ] ; then \
#	  $(CC) -o $(AESTEST)$(EXE_EXT) $(CFLAGS_test) $(AESTEST).o $(PEX_LIBS) $(DLIBCRYPTO_test) $(EX_LIBS) ; \
#	else \
#	  $(CC) -o $(AESTEST)$(EXE_EXT) $(CFLAGS_test) $(AESTEST).o $(PEX_LIBS) $(LIBCRYPTO_test) $(EX_LIBS) ; \
#	fi

dummytest$(EXE_EXT): dummytest.o $(DLIBCRYPTO_test)
	@target=dummytest; $(BUILD_CMD_test)

.c.o:
	$(CC) $(CFLAGS_test) $(CPPFLAGS) -c -o $@ $<
