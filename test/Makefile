#
# test/Makefile
#

INCLUDES_test=	-I. -Iinclude $(KRB5_INCLUDES) -Ifips
# KRB5 stuff
TEST_test=		test/fips_algvs.c test/igetest.c


CFLAGS_test= $(INCLUDES_test) $(CFLAG)

GENERAL_test=test/Makefile test/maketests.com \
	test/tests.com test/testenc.com test/tx509.com test/trsa.com test/tcrl.com test/tsid.com test/treq.com \
	test/tpkcs7.com test/tpkcs7d.com test/tverify.com test/testgen.com test/testss.com test/testssl.com \
	test/testca.com test/VMSca-response.1 test/VMSca-response.2

DLIBCRYPTO_test= libcrypto.a
DLIBSSL_test= libssl.a
LIBCRYPTO_test= -L. -lcrypto
LIBSSL_test= -L. -lssl
LIBFIPS= -L. -lfips

BNTEST=		test/bntest
ECTEST=		test/ectest
ECDSATEST=	test/ecdsatest
ECDHTEST=	test/ecdhtest
EXPTEST=	test/exptest
IDEATEST=	test/ideatest
SHATEST=	test/shatest
SHA1TEST=	test/sha1test
SHA256TEST=	test/sha256t
SHA512TEST=	test/sha512t
MDC2TEST=	test/mdc2test
RMDTEST=	test/rmdtest
MD2TEST=	test/md2test
MD4TEST=	test/md4test
MD5TEST=	test/md5test
HMACTEST=	test/hmactest
WPTEST=		test/wp_test
RC2TEST=	test/rc2test
RC4TEST=	test/rc4test
RC5TEST=	test/rc5test
BFTEST=		test/bftest
CASTTEST=	test/casttest
DESTEST=	test/destest
GOST2814789TEST=test/gost2814789t
RANDTEST=	test/randtest
DHTEST=		test/dhtest
DSATEST=	test/dsatest
METHTEST=	test/methtest
SSLTEST=	test/ssltest
RSATEST=	test/rsa_test
ENGINETEST=	test/enginetest
EVPTEST=	test/evp_test
P5_CRPT2_TEST=	test/p5_crpt2_test
IGETEST=	test/igetest
JPAKETEST=	test/jpaketest
SRPTEST=	test/srptest
V3NAMETEST=	test/v3nametest
FIPS_SHATEST=	test/fips_shatest
FIPS_DESTEST=	test/fips_desmovs
FIPS_RANDTEST=	test/fips_randtest
FIPS_AESTEST=	test/fips_aesavs
FIPS_GCMTEST=	test/fips_gcmtest
FIPS_HMACTEST=	test/fips_hmactest
FIPS_RSAVTEST=	test/fips_rsavtest
FIPS_RSASTEST=	test/fips_rsastest
FIPS_RSAGTEST=	test/fips_rsagtest
FIPS_DSATEST=	test/fips_dsatest
FIPS_DSSVS=	test/fips_dssvs
FIPS_RNGVS=	test/fips_rngvs
FIPS_DRBGVS=	test/fips_drbgvs
FIPS_DHVS=	test/fips_dhvs
FIPS_ECDHVS=	test/fips_ecdhvs
FIPS_ECDSAVS=	test/fips_ecdsavs
FIPS_TEST_SUITE=test/fips_test_suite
FIPS_CMACTEST=	test/fips_cmactest
FIPS_ALGVS=	test/fips_algvs
HEARTBEATTEST=  test/heartbeat_test
CONSTTIMETEST=  test/constant_time_test

TESTS_test=		test/alltests

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
	$(CONSTTIMETEST).o test/testutil.o

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
	$(CONSTTIMETEST).c test/testutil.c

EXHEADER_test= 
HEADER_test=	test/testutil.h $(EXHEADER_test)

ALL_test=    $(GENERAL_test) $(SRC_test) $(HEADER_test)


all: all_test
all_test:	exe_test

exe: exe_test
exe_test:	$(EXE_test) $(FIPSEXE) test/dummytest$(EXE_EXT)

test/fipsexe:	$(FIPSEXE)

test/fipsalgvs:	$(FIPS_ALGVS)

files: files_test
files_test:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_test
links_test:

test/generate: $(SRC_test)
$(SRC_test):
	@sh util/point.sh test/dummytest.c $@

errors: errors_test
errors_test:

install: install_test
install_test:

tags: tags_test
tags_test:
	ctags $(SRC_test)

tests: tests_test
tests_test: test/alltests

test/alltests: rehash exe_test all_apps \
	test/test_des test/test_idea test/test_sha test/test_md4 test/test_md5 test/test_hmac \
	test/test_md2 test/test_mdc2 test/test_wp \
	test/test_rmd test/test_rc2 test/test_rc4 test/test_rc5 test/test_bf test/test_cast \
	test/test_rand test/test_bn test/test_ec test/test_ecdsa test/test_ecdh \
	test/test_enc test/test_x509 test/test_rsa test/test_crl test/test_sid \
	test/test_gen test/test_req test/test_pkcs7 test/test_verify test/test_dh test/test_dsa \
	test/test_ss test/test_ca test/test_engine test/test_evp test/test_ssl test/test_tsa test/test_ige \
	test/test_jpake test/test_srp test/test_cms test/test_v3name test/test_ocsp \
	test/test_gost2814789 test/test_heartbeat test/test_p5_crpt2 \
	test/test_constant_time

test/test_evp: $(EVPTEST)$(EXE_EXT) test/evptests.txt
	util/shlib_wrap.sh $(EVPTEST) test/evptests.txt

test/test_p5_crpt2: $(P5_CRPT2_TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(P5_CRPT2_TEST)

test/test_des: $(DESTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(DESTEST)

test/test_idea: $(IDEATEST)$(EXE_EXT)
	util/shlib_wrap.sh $(IDEATEST)

test/test_sha: $(SHATEST)$(EXE_EXT) $(SHA1TEST)$(EXE_EXT) $(SHA256TEST)$(EXE_EXT) $(SHA512TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(SHATEST)
	util/shlib_wrap.sh $(SHA1TEST)
	util/shlib_wrap.sh $(SHA256TEST)
	util/shlib_wrap.sh $(SHA512TEST)

test/test_mdc2: $(MDC2TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(MDC2TEST)

test/test_md5: $(MD5TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(MD5TEST)

test/test_md4: $(MD4TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(MD4TEST)

test/test_hmac: $(HMACTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(HMACTEST)

test/test_wp: $(WPTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(WPTEST)

test/test_md2: $(MD2TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(MD2TEST)

test/test_rmd: $(RMDTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(RMDTEST)

test/test_bf: $(BFTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(BFTEST)

test/test_cast: $(CASTTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(CASTTEST)

test/test_rc2: $(RC2TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(RC2TEST)

test/test_rc4: $(RC4TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(RC4TEST)

test/test_rc5: $(RC5TEST)$(EXE_EXT)
	util/shlib_wrap.sh $(RC5TEST)

test/test_rand: $(RANDTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(RANDTEST)

test/test_gost2814789: $(GOST2814789TEST)$(EXE_EXT)
	OPENSSL_ENGINES=engines/ccgost util/shlib_wrap.sh $(GOST2814789TEST)

test/test_enc: apps/openssl$(EXE_EXT) test/testenc
	@sh test/testenc

test/test_x509: apps/openssl$(EXE_EXT) test/tx509 test/testx509.pem test/v3-cert1.pem test/v3-cert2.pem
	echo test normal x509v1 certificate
	sh test/tx509 2>/dev/null
	echo test first x509v3 certificate
	sh test/tx509 test/v3-cert1.pem 2>/dev/null
	echo test second x509v3 certificate
	sh test/tx509 test/v3-cert2.pem 2>/dev/null

test/test_rsa: $(RSATEST)$(EXE_EXT) apps/openssl$(EXE_EXT) test/trsa test/testrsa.pem
	@sh test/trsa 2>/dev/null
	util/shlib_wrap.sh $(RSATEST)

test/test_crl: apps/openssl$(EXE_EXT) test/tcrl test/testcrl.pem
	@sh test/tcrl 2>/dev/null

test/test_sid: apps/openssl$(EXE_EXT) test/tsid test/testsid.pem
	@sh test/tsid 2>/dev/null

test/test_req: apps/openssl$(EXE_EXT) test/treq test/testreq.pem test/testreq2.pem
	@sh test/treq 2>/dev/null
	@sh test/treq test/testreq2.pem 2>/dev/null

test/test_pkcs7: apps/openssl$(EXE_EXT) test/tpkcs7 test/tpkcs7d test/testp7.pem test/pkcs7-1.pem
	@sh test/tpkcs7 2>/dev/null
	@sh test/tpkcs7d 2>/dev/null

test/test_bn: $(BNTEST)$(EXE_EXT) $(EXPTEST)$(EXE_EXT) test/bctest
	@echo starting big number library test, could take a while...
	@util/shlib_wrap.sh $(BNTEST) >test/tmp.bntest
	@echo quit >>test/tmp.bntest
	@echo "running bc"
	@<test/tmp.bntest sh -c "`sh test/bctest ignore`" | $(PERL) -e '$$i=0; while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $$1";} elsif (!/^0\r?$$/) {die "\nFailed! bc: $$_";} else {print STDERR "."; $$i++;}} print STDERR "\n$$i test/tests passed\n"'
	@echo 'test a^b%c implementations'
	util/shlib_wrap.sh $(EXPTEST)

test/test_ec: $(ECTEST)$(EXE_EXT)
	@echo 'test elliptic curves'
	util/shlib_wrap.sh $(ECTEST)

test/test_ecdsa: $(ECDSATEST)$(EXE_EXT)
	@echo 'test ecdsa'
	util/shlib_wrap.sh $(ECDSATEST)

test/test_ecdh: $(ECDHTEST)$(EXE_EXT)
	@echo 'test ecdh'
	util/shlib_wrap.sh $(ECDHTEST)

test/test_verify: apps/openssl$(EXE_EXT)
	@echo "The following command should have some OK's and some failures"
	@echo "There are definitly a few expired certificates"
	util/shlib_wrap.sh apps/openssl verify -CApath certs/demo certs/demo/*.pem

test/test_dh: $(DHTEST)$(EXE_EXT)
	@echo "Generate a set of DH parameters"
	util/shlib_wrap.sh $(DHTEST)

test/test_dsa: $(DSATEST)$(EXE_EXT)
	@echo "Generate a set of DSA parameters"
	util/shlib_wrap.sh $(DSATEST)
	util/shlib_wrap.sh $(DSATEST) -app2_1

test/test_gen test/testreq.pem: apps/openssl$(EXE_EXT) test/testgen test/test.cnf
	@echo "Generate and verify a certificate request"
	@sh test/testgen

test/test_ss test/keyU.ss test/certU.ss test/certCA.ss test/certP1.ss test/keyP1.ss test/certP2.ss test/keyP2.ss \
		test/intP1.ss test/intP2.ss: test/testss test/CAss.cnf test/Uss.cnf test/P1ss.cnf test/P2ss.cnf \
                                   apps/openssl$(EXE_EXT)
	@echo "Generate and certify a test certificate"
	@sh test/testss
	@cat test/certCA.ss test/certU.ss > test/intP1.ss
	@cat test/certCA.ss test/certU.ss test/certP1.ss > test/intP2.ss

test/test_engine: $(ENGINETEST)$(EXE_EXT)
	@echo "Manipulate the ENGINE structures"
	util/shlib_wrap.sh $(ENGINETEST)

test/test_ssl: test/keyU.ss test/certU.ss test/certCA.ss test/certP1.ss test/keyP1.ss test/certP2.ss test/keyP2.ss \
		test/intP1.ss test/intP2.ss $(SSLTEST)$(EXE_EXT) test/testssl test/testsslproxy \
		apps/server2.pem test/serverinfo.pem
	@echo "test SSL protocol"
	util/shlib_wrap.sh $(SSLTEST) -test_cipherlist
	@sh test/testssl test/keyU.ss test/certU.ss test/certCA.ss
	@sh test/testsslproxy test/keyP1.ss test/certP1.ss test/intP1.ss
	@sh test/testsslproxy test/keyP2.ss test/certP2.ss test/intP2.ss

test/test_ca: apps/openssl$(EXE_EXT) test/testca test/CAss.cnf test/Uss.cnf
	@if util/shlib_wrap.sh apps/openssl no-rsa; then \
	  echo "skipping CA.sh test -- requires RSA"; \
	else \
	  echo "Generate and certify a test certificate via the 'ca' program"; \
	  sh test/testca; \
	fi

test/test_tsa: apps/openssl$(EXE_EXT) test/testtsa test/CAtsa.cnf util/shlib_wrap.sh
	@if util/shlib_wrap.sh apps/openssl no-rsa; then \
	  echo "skipping test/testtsa test -- requires RSA"; \
	else \
	  sh test/testtsa; \
	fi

test/test_ige: $(IGETEST)$(EXE_EXT)
	@echo "Test IGE mode"
	util/shlib_wrap.sh $(IGETEST)

test/test_jpake: $(JPAKETEST)$(EXE_EXT)
	@echo "Test JPAKE"
	util/shlib_wrap.sh $(JPAKETEST)

test/test_cms: apps/openssl$(EXE_EXT) test/cms-test.pl test/smcont.txt
	@echo "CMS consistency test"
	EXE_EXT="$(EXE_EXT)" $(PERL) test/cms-test.pl

test/test_srp: $(SRPTEST)$(EXE_EXT)
	@echo "Test SRP"
	util/shlib_wrap.sh test/srptest

test/test_v3name: $(V3NAMETEST)$(EXE_EXT)
	@echo "Test X509v3_check_*"
	util/shlib_wrap.sh $(V3NAMETEST)

test/test_ocsp: apps/openssl$(EXE_EXT) test/tocsp
	@echo "Test OCSP"
	@sh test/tocsp

test/test_heartbeat: $(HEARTBEATTEST)$(EXE_EXT)
	util/shlib_wrap.sh $(HEARTBEATTEST)

test/test_constant_time: $(CONSTTIMETEST)$(EXE_EXT)
	@echo "Test constant time utilites"
	util/shlib_wrap.sh $(CONSTTIMETEST)

lint: lint_test
lint_test:
	lint -DLINT $(INCLUDES_test) $(SRC_test)>test/fluff

dclean: dclean_test
dclean_test:
	rm -f $(SRC_test) $(SHA256TEST).c $(SHA512TEST).c test/evptests.txt test/newkey.pem test/testkey.pem \
			test/testreq.pem

clean: clean_test
clean_test:
	rm -f test/.rnd test/tmp.bntest test/tmp.bctest test/*.o test/*.d test/*.obj test/*.dll test/lib test/tags test/core test/.pure test/.nfs* test/*.old test/*.bak test/fluff $(EXE_test) $(FIPSEXE) test/*.ss test/*.srl test/log test/dummytest

BUILD_CMD_test=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL_test) $(LIBCRYPTO_test) $(LIBKRB5)"; \
	cat configure.mk Makefile.shared | $(MAKE) -f - \
		APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o $$testutil" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

BUILD_CMD_STATIC=shlib_target=; \
	LIBRARIES="$(DLIBSSL_test) $(DLIBCRYPTO_test) $(LIBKRB5)"; \
	cat configure.mk Makefile.shared | $(MAKE) -f - \
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
		LIBRARIES="-L. -lfips"; \
	elif [ -n "$(FIPSCANLIB)" ]; then \
		FIPSLD_CC="$(CC)"; CC=fips/fipsld; export CC FIPSLD_CC; \
		LIBRARIES="$${FIPSLIBDIR:-fips/}fipscanister.o"; \
	else \
		LIBRARIES="$(LIBCRYPTO_test)"; \
	fi; \
	cat configure.mk Makefile.shared | $(MAKE) -f - \
		CC="$(CC)" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

FIPS_CRYPTO_BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL_test) $(LIBCRYPTO_test) $(LIBKRB5)"; \
	if [ -z "$(SHARED_LIBS)" -a -n "$(FIPSCANLIB)" ] ; then \
		FIPSLD_CC="$(CC)"; CC=fips/fipsld; export CC FIPSLD_CC; \
	fi; \
	[ "$(FIPSCANLIB)" = "libfips" ] && LIBRARIES="$$LIBRARIES -lfips"; \
	cat configure.mk Makefile.shared | $(MAKE) -f - \
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

$(HEARTBEATTEST)$(EXE_EXT): $(HEARTBEATTEST).o $(DLIBCRYPTO_test) test/testutil.o
	@target=$(HEARTBEATTEST) testutil=test/testutil.o; $(BUILD_CMD_STATIC)

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

test/dummytest$(EXE_EXT): test/dummytest.o $(DLIBCRYPTO_test)
	@target=test/dummytest; $(BUILD_CMD_test)

