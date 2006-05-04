#
# test/Makefile
#

DIR=		test
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES)
CFLAG=		-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=	/usr/local/ssl
MAKEFILE=	Makefile
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
PERL=		perl
# KRB5 stuff
KRB5_INCLUDES=
LIBKRB5=

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

BNTEST=		bntest
ECTEST=		ectest
EXPTEST=	exptest
IDEATEST=	ideatest
SHATEST=	shatest
SHA1TEST=	sha1test
FIPS_SHATEST=	fips_shatest
MDC2TEST=	mdc2test
RMDTEST=	rmdtest
MD2TEST=	md2test
MD4TEST=	md4test
MD5TEST=	md5test
HMACTEST=	hmactest
RC2TEST=	rc2test
RC4TEST=	rc4test
RC5TEST=	rc5test
BFTEST=		bftest
CASTTEST=	casttest
DESTEST=	destest
FIPS_DESTEST=	fips_desmovs
RANDTEST=	randtest
FIPS_RANDTEST=	fips_randtest
DHTEST=		dhtest
DSATEST=	dsatest
FIPS_DSATEST=	fips_dsatest
METHTEST=	methtest
SSLTEST=	ssltest
RSATEST=	rsa_test
ENGINETEST=	enginetest
EVPTEST=	evp_test
FIPS_AESTEST=	fips_aesavs
FIPS_HMACTEST=	fips_hmactest
FIPS_RSAVTEST=	fips_rsavtest
FIPS_RSASTEST=	fips_rsastest
FIPS_RSAGTEST=	fips_rsagtest
FIPS_DSSVS=	fips_dssvs
FIPS_RNGVS=	fips_rngvs
FIPS_TEST_SUITE=fips_test_suite

TESTS=		alltests

EXE=	$(BNTEST)$(EXE_EXT) $(ECTEST)$(EXE_EXT) $(IDEATEST)$(EXE_EXT) $(MD2TEST)$(EXE_EXT)  $(MD4TEST)$(EXE_EXT) $(MD5TEST)$(EXE_EXT) $(HMACTEST)$(EXE_EXT) \
	$(RC2TEST)$(EXE_EXT) $(RC4TEST)$(EXE_EXT) $(RC5TEST)$(EXE_EXT) \
	$(DESTEST)$(EXE_EXT) $(FIPS_DESTEST)$(EXE_EXT) $(SHATEST)$(EXE_EXT) $(SHA1TEST)$(EXE_EXT) $(FIPS_SHATEST)$(EXE_EXT) $(MDC2TEST)$(EXE_EXT) $(RMDTEST)$(EXE_EXT) \
	$(RANDTEST)$(EXE_EXT) $(FIPS_RANDTEST)$(EXE_EXT) $(DHTEST)$(EXE_EXT) $(ENGINETEST)$(EXE_EXT) \
	$(BFTEST)$(EXE_EXT) $(CASTTEST)$(EXE_EXT) $(SSLTEST)$(EXE_EXT) $(EXPTEST)$(EXE_EXT) $(DSATEST)$(EXE_EXT) $(FIPS_DSATEST)$(EXE_EXT) $(RSATEST)$(EXE_EXT) \
	$(EVPTEST)$(EXE_EXT) $(FIPS_AESTEST)$(EXE_EXT) \
	$(FIPS_HMACTEST)$(EXE_EXT) $(FIPS_RSAVTEST)$(EXE_EXT) \
	$(FIPS_RSASTEST)$(EXE_EXT) $(FIPS_RSAGTEST)$(EXE_EXT) \
	$(FIPS_DSSVS)$(EXE_EXT) $(FIPS_RNGVS)$(EXE_EXT) \
	$(FIPS_TEST_SUITE)$(EXE_EXT)

# $(METHTEST)$(EXE_EXT)

OBJ=	$(BNTEST).o $(ECTEST).o $(IDEATEST).o $(MD2TEST).o $(MD4TEST).o $(MD5TEST).o \
	$(HMACTEST).o \
	$(RC2TEST).o $(RC4TEST).o $(RC5TEST).o \
	$(DESTEST).o $(FIPS_DESTEST).o $(SHATEST).o $(SHA1TEST).o $(FIPS_SHATEST).o $(MDC2TEST).o $(RMDTEST).o \
	$(RANDTEST).o $(FIPS_RANDTEST).o $(DHTEST).o $(ENGINETEST).o $(CASTTEST).o \
	$(BFTEST).o  $(SSLTEST).o  $(DSATEST).o $(FIPS_DSATEST).o $(EXPTEST).o $(RSATEST).o \
	$(EVPTEST).o $(FIPS_AESTEST).o $(FIPS_HMACTEST).o $(FIPS_RSAVTEST).o \
	$(FIPS_RSASTEST).o $(FIPS_RSAGTEST).o $(FIPS_DSSVS).o $(FIPS_RNGVS).o \
	$(FIPS_TEST_SUITE).o
SRC=	$(BNTEST).c $(ECTEST).c $(IDEATEST).c $(MD2TEST).c  $(MD4TEST).c $(MD5TEST).c \
	$(HMACTEST).c \
	$(RC2TEST).c $(RC4TEST).c $(RC5TEST).c \
	$(DESTEST).c $(FIPS_DESTEST).c $(SHATEST).c $(SHA1TEST).c $(FIPS_SHATEST).c $(MDC2TEST).c $(RMDTEST).c \
	$(RANDTEST).c $(FIPS_RANDTEST).c $(DHTEST).c $(ENGINETEST).c $(CASTTEST).c \
	$(BFTEST).c  $(SSLTEST).c $(DSATEST).c $(FIPS_DSATEST).c $(EXPTEST).c $(RSATEST).c \
	$(EVPTEST).c $(FIPS_AESTEST).c $(FIPS_HMACTEST).c $(FIPS_RSAVTEST).c \
	$(FIPS_RSASTEST).c $(FIPS_RSAGTEST).c $(FIPS_DSSVS).c $(FIPS_RNGVS).c \
	$(FIPS_TEST_SUITE).c

EXHEADER= 
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) TESTS=$(TESTS) all)

all:	exe

exe:	$(EXE) dummytest$(EXE_EXT)

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
	test_md2 test_mdc2 \
	test_rmd test_rc2 test_rc4 test_rc5 test_bf test_cast test_aes \
	test_rand test_bn test_ec test_enc test_x509 test_rsa test_crl test_sid \
	test_gen test_req test_pkcs7 test_verify test_dh test_dsa \
	test_ss test_ca test_engine test_evp test_ssl
# temporarily removed
# fips_test_aes

fips_test_aes:
	if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
	  mkdir -p fips_aes_data/rsp; \
	  ../util/shlib_wrap.sh ./$(FIPS_AESTEST) -d fips_aes_data/list; \
	fi

test_evp:
	../util/shlib_wrap.sh ./$(EVPTEST) evptests.txt

test_des:
	../util/shlib_wrap.sh ./$(DESTEST)

test_idea:
	../util/shlib_wrap.sh ./$(IDEATEST)

test_sha:
	../util/shlib_wrap.sh ./$(SHATEST)
	../util/shlib_wrap.sh ./$(SHA1TEST)
	if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
	  ../util/shlib_wrap.sh ./$(FIPS_SHATEST) < SHAmix.req | diff -w SHAmix.fax - ; \
	fi

test_mdc2:
	../util/shlib_wrap.sh ./$(MDC2TEST)

test_md5:
	../util/shlib_wrap.sh ./$(MD5TEST)

test_md4:
	../util/shlib_wrap.sh ./$(MD4TEST)

test_hmac:
	../util/shlib_wrap.sh ./$(HMACTEST)

test_md2:
	../util/shlib_wrap.sh ./$(MD2TEST)

test_rmd:
	../util/shlib_wrap.sh ./$(RMDTEST)

test_bf:
	../util/shlib_wrap.sh ./$(BFTEST)

test_cast:
	../util/shlib_wrap.sh ./$(CASTTEST)

test_rc2:
	../util/shlib_wrap.sh ./$(RC2TEST)

test_rc4:
	../util/shlib_wrap.sh ./$(RC4TEST)

test_rc5:
	../util/shlib_wrap.sh ./$(RC5TEST)

test_rand:
	../util/shlib_wrap.sh ./$(RANDTEST)
	if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
	  ../util/shlib_wrap.sh ./$(FIPS_RANDTEST); \
	fi

test_enc:
	@sh ./testenc

test_x509:
	echo test normal x509v1 certificate
	sh ./tx509 2>/dev/null
	echo test first x509v3 certificate
	sh ./tx509 v3-cert1.pem 2>/dev/null
	echo test second x509v3 certificate
	sh ./tx509 v3-cert2.pem 2>/dev/null

test_rsa:
	@sh ./trsa 2>/dev/null
	../util/shlib_wrap.sh ./$(RSATEST)

test_crl:
	@sh ./tcrl 2>/dev/null

test_sid:
	@sh ./tsid 2>/dev/null

test_req:
	@sh ./treq 2>/dev/null
	@sh ./treq testreq2.pem 2>/dev/null

test_pkcs7:
	@sh ./tpkcs7 2>/dev/null
	@sh ./tpkcs7d 2>/dev/null

test_bn:
	@echo starting big number library test, could take a while...
	@../util/shlib_wrap.sh ./$(BNTEST) >tmp.bntest
	@echo quit >>tmp.bntest
	@echo "running bc"
	@<tmp.bntest sh -c "`sh ./bctest ignore`" | $(PERL) -e '$$i=0; while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $$1";} elsif (!/^0$$/) {die "\nFailed! bc: $$_";} else {print STDERR "."; $$i++;}} print STDERR "\n$$i tests passed\n"'
	@echo 'test a^b%c implementations'
	../util/shlib_wrap.sh ./$(EXPTEST)

test_ec:
	@echo 'test elliptic curves'
	../util/shlib_wrap.sh ./$(ECTEST)

test_verify:
	@echo "The following command should have some OK's and some failures"
	@echo "There are definitly a few expired certificates"
	-../util/shlib_wrap.sh ../apps/openssl verify -CApath ../certs ../certs/*.pem

test_dh:
	@echo "Generate a set of DH parameters"
	../util/shlib_wrap.sh ./$(DHTEST)

test_dsa:
	@echo "Generate a set of DSA parameters"
	../util/shlib_wrap.sh ./$(DSATEST)
	../util/shlib_wrap.sh ./$(DSATEST) -app2_1
	if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
	  ../util/shlib_wrap.sh ./$(FIPS_DSATEST); \
	  ../util/shlib_wrap.sh ./$(FIPS_DSATEST) -app2_1; \
	fi

test_gen:
	@echo "Generate and verify a certificate request"
	@sh ./testgen

test_ss keyU.ss certU.ss certCA.ss certP1.ss keyP1.ss certP2.ss keyP2.ss \
		intP1.ss intP2.ss: testss
	@echo "Generate and certify a test certificate"
	@sh ./testss
	@cat certCA.ss certU.ss > intP1.ss
	@cat certCA.ss certU.ss certP1.ss > intP2.ss

test_engine: 
	@echo "Manipulate the ENGINE structures"
	../util/shlib_wrap.sh ./$(ENGINETEST)

test_ssl: keyU.ss certU.ss certCA.ss certP1.ss keyP1.ss certP2.ss keyP2.ss \
		intP1.ss intP2.ss
	@echo "test SSL protocol"
	@if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
	  sh ./testfipsssl keyU.ss certU.ss certCA.ss; \
	fi
	@sh ./testssl keyU.ss certU.ss certCA.ss
	@sh ./testsslproxy keyP1.ss certP1.ss intP1.ss
	@sh ./testsslproxy keyP2.ss certP2.ss intP2.ss

test_ca:
	@if ../util/shlib_wrap.sh ../apps/openssl no-rsa; then \
	  echo "skipping CA.sh test -- requires RSA"; \
	else \
	  echo "Generate and certify a test certificate via the 'ca' program"; \
	  sh ./testca; \
	fi

test_aes: #$(AESTEST)
#	@echo "test Rijndael"
#	../util/shlib_wrap.sh ./$(AESTEST)

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f .rnd tmp.bntest tmp.bctest *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE) *.ss *.srl log

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

BUILD_CMD=SHARED_LIBS="$(SHARED_LIBS)"; \
	if [ "$(SHLIB_TARGET)" = "darwin-shared" ] ; then \
		SHARED_LIBS=""; \
	fi; \
	if [ -z "$$SHARED_LIBS" ]; then \
		set -x; $${CC:-$(CC)} -o $$target$(EXE_EXT) $(CFLAGS) $$target.o $(PEX_LIBS) $(DLIBSSL) $(LIBKRB5) $(DLIBCRYPTO) $(EX_LIBS) ; \
	else	set -x; LD_LIBRARY_PATH=..:$$LD_LIBRARY_PATH \
		$(CC) -o $$target$(EXE_EXT) $(CFLAGS) $$target.o $(PEX_LIBS) $(LIBSSL) $(LIBKRB5) $(LIBCRYPTO) $(EX_LIBS) ; \
	fi

FIPS_BUILD_CMD=if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
	  FIPSLD_CC=$(CC); CC=$(TOP)/fips-1.0/fipsld; export CC FIPSLD_CC; \
	fi; $(BUILD_CMD)

$(FIPS_AESTEST)$(EXE_EXT): $(FIPS_AESTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_AESTEST); $(FIPS_BUILD_CMD)

$(FIPS_HMACTEST)$(EXE_EXT): $(FIPS_HMACTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_HMACTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSAVTEST)$(EXE_EXT): $(FIPS_RSAVTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RSAVTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSASTEST)$(EXE_EXT): $(FIPS_RSASTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RSASTEST); $(FIPS_BUILD_CMD)

$(FIPS_RSAGTEST)$(EXE_EXT): $(FIPS_RSAGTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RSAGTEST); $(FIPS_BUILD_CMD)

$(FIPS_DSSVS)$(EXE_EXT): $(FIPS_DSSVS).o $(DLIBCRYPTO)
	@target=$(FIPS_DSSVS); $(FIPS_BUILD_CMD)

$(FIPS_RNGVS)$(EXE_EXT): $(FIPS_RNGVS).o $(DLIBCRYPTO)
	@target=$(FIPS_RNGVS); $(FIPS_BUILD_CMD)

$(FIPS_TEST_SUITE)$(EXE_EXT): $(FIPS_TEST_SUITE).o $(DLIBCRYPTO)
	@target=$(FIPS_TEST_SUITE); $(FIPS_BUILD_CMD)

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

$(FIPS_SHATEST)$(EXE_EXT): $(FIPS_SHATEST).o $(DLIBCRYPTO)
	@target=$(FIPS_SHATEST); $(FIPS_BUILD_CMD)

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

$(FIPS_DESTEST)$(EXE_EXT): $(FIPS_DESTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_DESTEST); $(FIPS_BUILD_CMD)

$(RANDTEST)$(EXE_EXT): $(RANDTEST).o $(DLIBCRYPTO)
	@target=$(RANDTEST); $(BUILD_CMD)

$(FIPS_RANDTEST)$(EXE_EXT): $(FIPS_RANDTEST).o $(DLIBCRYPTO)
	@target=$(FIPS_RANDTEST); $(FIPS_BUILD_CMD)

$(DHTEST)$(EXE_EXT): $(DHTEST).o $(DLIBCRYPTO)
	@target=$(DHTEST); $(BUILD_CMD)

$(DSATEST)$(EXE_EXT): $(DSATEST).o $(DLIBCRYPTO)
	@target=$(DSATEST); $(BUILD_CMD)

$(FIPS_DSATEST)$(EXE_EXT): $(FIPS_DSATEST).o $(DLIBCRYPTO)
	@target=$(FIPS_DSATEST); $(FIPS_BUILD_CMD)

$(METHTEST)$(EXE_EXT): $(METHTEST).o $(DLIBCRYPTO)
	@target=$(METHTEST); $(BUILD_CMD)

$(SSLTEST)$(EXE_EXT): $(SSLTEST).o $(DLIBSSL) $(DLIBCRYPTO)
	@target=$(SSLTEST); $(FIPS_BUILD_CMD)

$(ENGINETEST)$(EXE_EXT): $(ENGINETEST).o $(DLIBCRYPTO)
	@target=$(ENGINETEST); $(BUILD_CMD)

$(EVPTEST)$(EXE_EXT): $(EVPTEST).o $(DLIBCRYPTO)
	@target=$(EVPTEST); $(BUILD_CMD)

#$(AESTEST).o: $(AESTEST).c
#	$(CC) -c $(CFLAGS) -DINTERMEDIATE_VALUE_KAT -DTRACE_KAT_MCT $(AESTEST).c

#$(AESTEST)$(EXE_EXT): $(AESTEST).o $(DLIBCRYPTO)
#	@target=$(AESTEST); $(BUILD_CMD)

dummytest$(EXE_EXT): dummytest.o $(DLIBCRYPTO)
	@target=dummytest; $(BUILD_CMD)

# DO NOT DELETE THIS LINE -- make depend depends on it.

bftest.o: ../e_os.h ../include/openssl/blowfish.h ../include/openssl/e_os2.h
bftest.o: ../include/openssl/opensslconf.h bftest.c
bntest.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
bntest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
bntest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
bntest.o: ../include/openssl/cast.h ../include/openssl/crypto.h
bntest.o: ../include/openssl/des.h ../include/openssl/des_old.h
bntest.o: ../include/openssl/dh.h ../include/openssl/dsa.h
bntest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
bntest.o: ../include/openssl/evp.h ../include/openssl/idea.h
bntest.o: ../include/openssl/lhash.h ../include/openssl/md2.h
bntest.o: ../include/openssl/md4.h ../include/openssl/md5.h
bntest.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
bntest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
bntest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
bntest.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
bntest.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
bntest.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
bntest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
bntest.o: ../include/openssl/sha.h ../include/openssl/stack.h
bntest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
bntest.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
bntest.o: ../include/openssl/x509_vfy.h bntest.c
casttest.o: ../e_os.h ../include/openssl/cast.h ../include/openssl/e_os2.h
casttest.o: ../include/openssl/opensslconf.h casttest.c
destest.o: ../include/openssl/crypto.h ../include/openssl/des.h
destest.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
destest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
destest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
destest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
destest.o: ../include/openssl/ui_compat.h destest.c
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
ectest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ectest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
ectest.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ectest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ectest.o: ../include/openssl/engine.h ../include/openssl/err.h
ectest.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
ectest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ectest.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ectest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
ectest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h ectest.c
enginetest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
enginetest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
enginetest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
enginetest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
enginetest.o: ../include/openssl/engine.h ../include/openssl/err.h
enginetest.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
enginetest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
enginetest.o: ../include/openssl/rand.h ../include/openssl/rsa.h
enginetest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
enginetest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
enginetest.o: enginetest.c
evp_test.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
evp_test.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
evp_test.o: ../include/openssl/bn.h ../include/openssl/cast.h
evp_test.o: ../include/openssl/conf.h ../include/openssl/crypto.h
evp_test.o: ../include/openssl/des.h ../include/openssl/des_old.h
evp_test.o: ../include/openssl/dh.h ../include/openssl/dsa.h
evp_test.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
evp_test.o: ../include/openssl/err.h ../include/openssl/evp.h
evp_test.o: ../include/openssl/idea.h ../include/openssl/lhash.h
evp_test.o: ../include/openssl/md2.h ../include/openssl/md4.h
evp_test.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
evp_test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
evp_test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
evp_test.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
evp_test.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
evp_test.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
evp_test.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
evp_test.o: ../include/openssl/sha.h ../include/openssl/stack.h
evp_test.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
evp_test.o: ../include/openssl/ui_compat.h evp_test.c
exptest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
exptest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
exptest.o: ../include/openssl/err.h ../include/openssl/lhash.h
exptest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
exptest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
exptest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
exptest.o: ../include/openssl/symhacks.h exptest.c
fips_aesavs.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
fips_aesavs.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_aesavs.o: ../include/openssl/bn.h ../include/openssl/cast.h
fips_aesavs.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_aesavs.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_aesavs.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_aesavs.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_aesavs.o: ../include/openssl/fips.h ../include/openssl/idea.h
fips_aesavs.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_aesavs.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_aesavs.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_aesavs.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_aesavs.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_aesavs.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
fips_aesavs.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
fips_aesavs.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
fips_aesavs.o: ../include/openssl/sha.h ../include/openssl/stack.h
fips_aesavs.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
fips_aesavs.o: ../include/openssl/ui_compat.h fips_aesavs.c
fips_desmovs.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
fips_desmovs.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_desmovs.o: ../include/openssl/bn.h ../include/openssl/cast.h
fips_desmovs.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_desmovs.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_desmovs.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_desmovs.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_desmovs.o: ../include/openssl/fips.h ../include/openssl/idea.h
fips_desmovs.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_desmovs.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_desmovs.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_desmovs.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_desmovs.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_desmovs.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
fips_desmovs.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
fips_desmovs.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
fips_desmovs.o: ../include/openssl/sha.h ../include/openssl/stack.h
fips_desmovs.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
fips_desmovs.o: ../include/openssl/ui_compat.h fips_desmovs.c
fips_dsatest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
fips_dsatest.o: ../include/openssl/bn.h ../include/openssl/crypto.h
fips_dsatest.o: ../include/openssl/des.h ../include/openssl/des_old.h
fips_dsatest.o: ../include/openssl/dh.h ../include/openssl/dsa.h
fips_dsatest.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
fips_dsatest.o: ../include/openssl/err.h ../include/openssl/fips.h
fips_dsatest.o: ../include/openssl/fips_rand.h ../include/openssl/lhash.h
fips_dsatest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_dsatest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
fips_dsatest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
fips_dsatest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_dsatest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_dsatest.o: fips_dsatest.c
fips_dssvs.o: ../include/openssl/opensslconf.h fips_dssvs.c
fips_hmactest.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips_hmactest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_hmactest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
fips_hmactest.o: ../include/openssl/cast.h ../include/openssl/conf.h
fips_hmactest.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_hmactest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_hmactest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_hmactest.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_hmactest.o: ../include/openssl/hmac.h ../include/openssl/idea.h
fips_hmactest.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_hmactest.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_hmactest.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_hmactest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_hmactest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_hmactest.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
fips_hmactest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
fips_hmactest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
fips_hmactest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
fips_hmactest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_hmactest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_hmactest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
fips_hmactest.o: ../include/openssl/x509v3.h fips_hmactest.c
fips_randtest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/crypto.h
fips_randtest.o: ../include/openssl/des.h ../include/openssl/des_old.h
fips_randtest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
fips_randtest.o: ../include/openssl/fips_rand.h ../include/openssl/lhash.h
fips_randtest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_randtest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
fips_randtest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
fips_randtest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
fips_randtest.o: ../include/openssl/ui_compat.h fips_randtest.c
fips_rngvs.o: ../include/openssl/opensslconf.h fips_rngvs.c
fips_rsagtest.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips_rsagtest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_rsagtest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
fips_rsagtest.o: ../include/openssl/cast.h ../include/openssl/conf.h
fips_rsagtest.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_rsagtest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_rsagtest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_rsagtest.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_rsagtest.o: ../include/openssl/hmac.h ../include/openssl/idea.h
fips_rsagtest.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_rsagtest.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_rsagtest.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_rsagtest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_rsagtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_rsagtest.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
fips_rsagtest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
fips_rsagtest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
fips_rsagtest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
fips_rsagtest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_rsagtest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_rsagtest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
fips_rsagtest.o: ../include/openssl/x509v3.h fips_rsagtest.c
fips_rsastest.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips_rsastest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_rsastest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
fips_rsastest.o: ../include/openssl/cast.h ../include/openssl/conf.h
fips_rsastest.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_rsastest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_rsastest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_rsastest.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_rsastest.o: ../include/openssl/hmac.h ../include/openssl/idea.h
fips_rsastest.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_rsastest.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_rsastest.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_rsastest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_rsastest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_rsastest.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
fips_rsastest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
fips_rsastest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
fips_rsastest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
fips_rsastest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_rsastest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_rsastest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
fips_rsastest.o: ../include/openssl/x509v3.h fips_rsastest.c
fips_rsavtest.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips_rsavtest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_rsavtest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
fips_rsavtest.o: ../include/openssl/cast.h ../include/openssl/conf.h
fips_rsavtest.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_rsavtest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_rsavtest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_rsavtest.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_rsavtest.o: ../include/openssl/hmac.h ../include/openssl/idea.h
fips_rsavtest.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_rsavtest.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_rsavtest.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_rsavtest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips_rsavtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_rsavtest.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
fips_rsavtest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
fips_rsavtest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
fips_rsavtest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
fips_rsavtest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_rsavtest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_rsavtest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
fips_rsavtest.o: ../include/openssl/x509v3.h fips_rsavtest.c
fips_shatest.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips_shatest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_shatest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
fips_shatest.o: ../include/openssl/cast.h ../include/openssl/conf.h
fips_shatest.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_shatest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_shatest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_shatest.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_shatest.o: ../include/openssl/idea.h ../include/openssl/lhash.h
fips_shatest.o: ../include/openssl/md2.h ../include/openssl/md4.h
fips_shatest.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
fips_shatest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
fips_shatest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
fips_shatest.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
fips_shatest.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
fips_shatest.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
fips_shatest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
fips_shatest.o: ../include/openssl/sha.h ../include/openssl/stack.h
fips_shatest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
fips_shatest.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
fips_shatest.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
fips_shatest.o: fips_shatest.c
fips_test_suite.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips_test_suite.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips_test_suite.o: ../include/openssl/bn.h ../include/openssl/cast.h
fips_test_suite.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips_test_suite.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips_test_suite.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips_test_suite.o: ../include/openssl/err.h ../include/openssl/evp.h
fips_test_suite.o: ../include/openssl/fips.h ../include/openssl/fips_sha.h
fips_test_suite.o: ../include/openssl/hmac.h ../include/openssl/idea.h
fips_test_suite.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips_test_suite.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips_test_suite.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips_test_suite.o: ../include/openssl/objects.h
fips_test_suite.o: ../include/openssl/opensslconf.h
fips_test_suite.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips_test_suite.o: ../include/openssl/rand.h ../include/openssl/rc2.h
fips_test_suite.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
fips_test_suite.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
fips_test_suite.o: ../include/openssl/safestack.h ../include/openssl/sha.h
fips_test_suite.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips_test_suite.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
fips_test_suite.o: fips_test_suite.c
hmactest.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
hmactest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
hmactest.o: ../include/openssl/bn.h ../include/openssl/cast.h
hmactest.o: ../include/openssl/crypto.h ../include/openssl/des.h
hmactest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
hmactest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
hmactest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
hmactest.o: ../include/openssl/idea.h ../include/openssl/md2.h
hmactest.o: ../include/openssl/md4.h ../include/openssl/md5.h
hmactest.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
hmactest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
hmactest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
hmactest.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
hmactest.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
hmactest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
hmactest.o: ../include/openssl/sha.h ../include/openssl/stack.h
hmactest.o: ../include/openssl/symhacks.h ../include/openssl/ui.h
hmactest.o: ../include/openssl/ui_compat.h hmactest.c
ideatest.o: ../e_os.h ../include/openssl/e_os2.h ../include/openssl/idea.h
ideatest.o: ../include/openssl/opensslconf.h ideatest.c
md2test.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
md2test.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
md2test.o: ../include/openssl/bn.h ../include/openssl/cast.h
md2test.o: ../include/openssl/crypto.h ../include/openssl/des.h
md2test.o: ../include/openssl/des_old.h ../include/openssl/dh.h
md2test.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
md2test.o: ../include/openssl/evp.h ../include/openssl/idea.h
md2test.o: ../include/openssl/md2.h ../include/openssl/md4.h
md2test.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
md2test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
md2test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
md2test.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
md2test.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
md2test.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
md2test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
md2test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
md2test.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h md2test.c
md4test.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
md4test.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
md4test.o: ../include/openssl/bn.h ../include/openssl/cast.h
md4test.o: ../include/openssl/crypto.h ../include/openssl/des.h
md4test.o: ../include/openssl/des_old.h ../include/openssl/dh.h
md4test.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
md4test.o: ../include/openssl/evp.h ../include/openssl/idea.h
md4test.o: ../include/openssl/md2.h ../include/openssl/md4.h
md4test.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
md4test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
md4test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
md4test.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
md4test.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
md4test.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
md4test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
md4test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
md4test.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h md4test.c
md5test.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
md5test.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
md5test.o: ../include/openssl/bn.h ../include/openssl/cast.h
md5test.o: ../include/openssl/crypto.h ../include/openssl/des.h
md5test.o: ../include/openssl/des_old.h ../include/openssl/dh.h
md5test.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
md5test.o: ../include/openssl/evp.h ../include/openssl/idea.h
md5test.o: ../include/openssl/md2.h ../include/openssl/md4.h
md5test.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
md5test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
md5test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
md5test.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
md5test.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
md5test.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
md5test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
md5test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
md5test.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h md5test.c
mdc2test.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
mdc2test.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
mdc2test.o: ../include/openssl/bn.h ../include/openssl/cast.h
mdc2test.o: ../include/openssl/crypto.h ../include/openssl/des.h
mdc2test.o: ../include/openssl/des_old.h ../include/openssl/dh.h
mdc2test.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
mdc2test.o: ../include/openssl/evp.h ../include/openssl/idea.h
mdc2test.o: ../include/openssl/md2.h ../include/openssl/md4.h
mdc2test.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
mdc2test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
mdc2test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mdc2test.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
mdc2test.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
mdc2test.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
mdc2test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
mdc2test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
mdc2test.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h mdc2test.c
randtest.o: ../e_os.h ../include/openssl/e_os2.h
randtest.o: ../include/openssl/opensslconf.h ../include/openssl/ossl_typ.h
randtest.o: ../include/openssl/rand.h randtest.c
rc2test.o: ../e_os.h ../include/openssl/e_os2.h
rc2test.o: ../include/openssl/opensslconf.h ../include/openssl/rc2.h rc2test.c
rc4test.o: ../e_os.h ../include/openssl/e_os2.h
rc4test.o: ../include/openssl/opensslconf.h ../include/openssl/rc4.h rc4test.c
rc5test.o: ../e_os.h ../include/openssl/e_os2.h
rc5test.o: ../include/openssl/opensslconf.h ../include/openssl/rc5.h rc5test.c
rmdtest.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
rmdtest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
rmdtest.o: ../include/openssl/bn.h ../include/openssl/cast.h
rmdtest.o: ../include/openssl/crypto.h ../include/openssl/des.h
rmdtest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
rmdtest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
rmdtest.o: ../include/openssl/evp.h ../include/openssl/idea.h
rmdtest.o: ../include/openssl/md2.h ../include/openssl/md4.h
rmdtest.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
rmdtest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rmdtest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rmdtest.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
rmdtest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
rmdtest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
rmdtest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rmdtest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rmdtest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h rmdtest.c
rsa_test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa_test.o: ../include/openssl/bn.h ../include/openssl/crypto.h
rsa_test.o: ../include/openssl/e_os2.h ../include/openssl/err.h
rsa_test.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
rsa_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa_test.o: ../include/openssl/rand.h ../include/openssl/rsa.h
rsa_test.o: ../include/openssl/safestack.h ../include/openssl/stack.h
rsa_test.o: ../include/openssl/symhacks.h rsa_test.c
sha1test.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
sha1test.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
sha1test.o: ../include/openssl/bn.h ../include/openssl/cast.h
sha1test.o: ../include/openssl/crypto.h ../include/openssl/des.h
sha1test.o: ../include/openssl/des_old.h ../include/openssl/dh.h
sha1test.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
sha1test.o: ../include/openssl/evp.h ../include/openssl/idea.h
sha1test.o: ../include/openssl/md2.h ../include/openssl/md4.h
sha1test.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
sha1test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sha1test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sha1test.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
sha1test.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
sha1test.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
sha1test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sha1test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
sha1test.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h sha1test.c
shatest.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
shatest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
shatest.o: ../include/openssl/bn.h ../include/openssl/cast.h
shatest.o: ../include/openssl/crypto.h ../include/openssl/des.h
shatest.o: ../include/openssl/des_old.h ../include/openssl/dh.h
shatest.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
shatest.o: ../include/openssl/evp.h ../include/openssl/idea.h
shatest.o: ../include/openssl/md2.h ../include/openssl/md4.h
shatest.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
shatest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
shatest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
shatest.o: ../include/openssl/ossl_typ.h ../include/openssl/rc2.h
shatest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
shatest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
shatest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
shatest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
shatest.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h shatest.c
ssltest.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
ssltest.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
ssltest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssltest.o: ../include/openssl/cast.h ../include/openssl/comp.h
ssltest.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ssltest.o: ../include/openssl/des.h ../include/openssl/des_old.h
ssltest.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ssltest.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
ssltest.o: ../include/openssl/err.h ../include/openssl/evp.h
ssltest.o: ../include/openssl/fips.h ../include/openssl/idea.h
ssltest.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssltest.o: ../include/openssl/md2.h ../include/openssl/md4.h
ssltest.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
ssltest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssltest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssltest.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssltest.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssltest.o: ../include/openssl/rand.h ../include/openssl/rc2.h
ssltest.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
ssltest.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
ssltest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssltest.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssltest.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssltest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssltest.o: ../include/openssl/tls1.h ../include/openssl/ui.h
ssltest.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
ssltest.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h ssltest.c
