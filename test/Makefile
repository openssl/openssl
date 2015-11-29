#
# test/Makefile
#

DIR=		test
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include -I../crypto/include -I$(TOP)/fips
CFLAG=		-g
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
PERL=		perl

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

# Prefix for logline for each test
START= @@@ START

NPTEST=		nptest
BNTEST=		bntest
ECTEST=		ectest
ECDSATEST=	ecdsatest
ECDHTEST=	ecdhtest
EXPTEST=	exptest
GMDIFFTEST=	gmdifftest
PBELUTEST=	pbelutest
IDEATEST=	ideatest
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
GOST2814789TEST=gost2814789test
RANDTEST=	randtest
DHTEST=		dhtest
DSATEST=	dsatest
SSLTEST=	ssltest
RSATEST=	rsa_test
ENGINETEST=	enginetest
EVPTEST=	evp_test
EVPEXTRATEST=evp_extra_test
P5_CRPT2_TEST=	p5_crpt2_test
IGETEST=	igetest
JPAKETEST=	jpaketest
SECMEMTEST=	secmemtest
SRPTEST=	srptest
V3NAMETEST=	v3nametest
HEARTBEATTEST=  heartbeat_test
CONSTTIMETEST=  constant_time_test
VERIFYEXTRATEST=	verify_extra_test
CLIENTHELLOTEST=	clienthellotest
PACKETTEST=	packettest
SSLVERTOLTEST=	sslvertoltest
SSLEXTENSIONTEST=	sslextensiontest
SSLSESSIONTICKTEST= 	sslsessionticktest
SSLSKEWITH0PTEST=	sslskewith0ptest
ASYNCTEST=	asynctest

TESTS=		alltests

EXE=	$(NPTEST)$(EXE_EXT) $(BNTEST)$(EXE_EXT) $(ECTEST)$(EXE_EXT) \
	$(ECDSATEST)$(EXE_EXT) $(ECDHTEST)$(EXE_EXT) $(GMDIFFTEST)$(EXE_EXT) \
	$(PBELUTEST)$(EXE_EXT) $(IDEATEST)$(EXE_EXT) \
	$(MD2TEST)$(EXE_EXT)  $(MD4TEST)$(EXE_EXT) $(MD5TEST)$(EXE_EXT) $(HMACTEST)$(EXE_EXT) $(WPTEST)$(EXE_EXT) \
	$(RC2TEST)$(EXE_EXT) $(RC4TEST)$(EXE_EXT) $(RC5TEST)$(EXE_EXT) \
	$(DESTEST)$(EXE_EXT) $(SHA1TEST)$(EXE_EXT) $(SHA256TEST)$(EXE_EXT) $(SHA512TEST)$(EXE_EXT) \
	$(MDC2TEST)$(EXE_EXT) $(RMDTEST)$(EXE_EXT) \
	$(RANDTEST)$(EXE_EXT) $(DHTEST)$(EXE_EXT) $(ENGINETEST)$(EXE_EXT) \
	$(GOST2814789TEST)$(EXE_EXT) \
	$(BFTEST)$(EXE_EXT) $(CASTTEST)$(EXE_EXT) $(SSLTEST)$(EXE_EXT) \
	$(EXPTEST)$(EXE_EXT) $(DSATEST)$(EXE_EXT) $(RSATEST)$(EXE_EXT) \
	$(EVPTEST)$(EXE_EXT) $(EVPEXTRATEST)$(EXE_EXT) $(IGETEST)$(EXE_EXT) \
	$(JPAKETEST)$(EXE_EXT) $(SECMEMTEST)$(EXE_EXT) \
	$(SRPTEST)$(EXE_EXT) $(V3NAMETEST)$(EXE_EXT) \
	$(HEARTBEATTEST)$(EXE_EXT) $(P5_CRPT2_TEST)$(EXE_EXT) \
	$(CONSTTIMETEST)$(EXE_EXT) $(VERIFYEXTRATEST)$(EXE_EXT) \
	$(CLIENTHELLOTEST)$(EXE_EXT) $(PACKETTEST)$(EXE_EXT) $(ASYNCTEST)$(EXE_EXT)

# $(METHTEST)$(EXE_EXT)

OBJ=	$(NPTEST).o $(BNTEST).o $(ECTEST).o \
	$(ECDSATEST).o $(ECDHTEST).o $(GMDIFFTEST).o $(PBELUTEST).o $(IDEATEST).o \
	$(MD2TEST).o $(MD4TEST).o $(MD5TEST).o \
	$(HMACTEST).o $(WPTEST).o \
	$(RC2TEST).o $(RC4TEST).o $(RC5TEST).o \
	$(DESTEST).o $(SHA1TEST).o $(SHA256TEST).o $(SHA512TEST).o \
	$(MDC2TEST).o $(RMDTEST).o \
	$(RANDTEST).o $(DHTEST).o $(ENGINETEST).o $(CASTTEST).o \
	$(BFTEST).o  $(SSLTEST).o  $(DSATEST).o  $(EXPTEST).o $(RSATEST).o \
	$(EVPTEST).o $(EVPEXTRATEST).o $(IGETEST).o $(JPAKETEST).o $(V3NAMETEST).o \
	$(GOST2814789TEST).o $(HEARTBEATTEST).o $(P5_CRPT2_TEST).o \
	$(CONSTTIMETEST).o $(VERIFYEXTRATEST).o $(CLIENTHELLOTEST).o \
	$(PACKETTEST).o $(ASYNCTEST).o testutil.o

SRC=	$(NPTEST).c $(BNTEST).c $(ECTEST).c \
	$(ECDSATEST).c $(ECDHTEST).c $(GMDIFFTEST).c $(PBELUTEST).c $(IDEATEST).c \
	$(MD2TEST).c  $(MD4TEST).c $(MD5TEST).c \
	$(HMACTEST).c $(WPTEST).c \
	$(RC2TEST).c $(RC4TEST).c $(RC5TEST).c \
	$(DESTEST).c $(SHA1TEST).c $(MDC2TEST).c $(RMDTEST).c \
	$(RANDTEST).c $(DHTEST).c $(ENGINETEST).c $(CASTTEST).c \
	$(BFTEST).c  $(SSLTEST).c $(DSATEST).c   $(EXPTEST).c $(RSATEST).c \
	$(EVPTEST).c $(EVPEXTRATEST).c $(IGETEST).c $(JPAKETEST).c $(V3NAMETEST).c \
	$(GOST2814789TEST).c $(HEARTBEATTEST).c $(P5_CRPT2_TEST).c \
	$(CONSTTIMETEST).c $(VERIFYEXTRATEST).c $(CLIENTHELLOTEST).c \
	$(PACKETTEST).c $(ASYNCTEST).c testutil.c

HEADER=	testutil.h

ALL=	$(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) TESTS=$(TESTS) all)

all:	exe

exe:	$(EXE) dummytest$(EXE_EXT)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

generate: $(SRC)
$(SRC):
	@sh $(TOP)/util/point.sh dummytest.c $@

errors:

tags:
	ctags $(SRC)

tests:	exe apps
	TOP=$(TOP) PERL=$(PERL) $(PERL) run_tests.pl $(TESTS)
list-tests:
	@TOP=$(TOP) PERL=$(PERL) $(PERL) run_tests.pl list

apps:
	@(cd ..; $(MAKE) DIRS=apps all)

update: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f newkey.pem testkey.pem testreq.pem

clean:
	rm -f .rnd tmp.bntest tmp.bctest *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE) *.ss *.srl log *.log dummytest

$(DLIBSSL):
	(cd ..; $(MAKE) build_libssl)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) build_libcrypto)

BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO)"; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o $$testutil" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

BUILD_CMD_STATIC=shlib_target=; \
	LIBRARIES="$(DLIBSSL) $(DLIBCRYPTO)"; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o $$testutil" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

$(RSATEST)$(EXE_EXT): $(RSATEST).o $(DLIBCRYPTO)
	@target=$(RSATEST); $(BUILD_CMD)

$(NPTEST)$(EXE_EXT): $(NPTEST).o $(DLIBCRYPTO)
	@target=$(NPTEST); $(BUILD_CMD)

$(BNTEST)$(EXE_EXT): $(BNTEST).o $(DLIBCRYPTO)
	@target=$(BNTEST); $(BUILD_CMD)

$(ECTEST)$(EXE_EXT): $(ECTEST).o $(DLIBCRYPTO)
	@target=$(ECTEST); $(BUILD_CMD)

$(EXPTEST)$(EXE_EXT): $(EXPTEST).o $(DLIBCRYPTO)
	@target=$(EXPTEST); $(BUILD_CMD)

$(IDEATEST)$(EXE_EXT): $(IDEATEST).o $(DLIBCRYPTO)
	@target=$(IDEATEST); $(BUILD_CMD)

$(GMDIFFTEST)$(EXE_EXT): $(GMDIFFTEST).o $(DLIBCRYPTO)
	@target=$(GMDIFFTEST); $(BUILD_CMD)

$(PBELUTEST)$(EXE_EXT): $(PBELUTEST).o $(DLIBCRYPTO)
	@target=$(PBELUTEST); $(BUILD_CMD)

$(MD2TEST)$(EXE_EXT): $(MD2TEST).o $(DLIBCRYPTO)
	@target=$(MD2TEST); $(BUILD_CMD)

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
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO)"; \
	if [ -z "$(SHARED_LIBS)" -a -n "$(FIPSCANLIB)" ] ; then \
		FIPSLD_CC="$(CC)"; CC=$(TOP)/fips/fipsld; export CC FIPSLD_CC; \
	fi; \
	[ "$(FIPSCANLIB)" = "libfips" ] && LIBRARIES="$$LIBRARIES -lfips"; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		CC="$${CC}" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

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

$(EVPEXTRATEST)$(EXE_EXT): $(EVPEXTRATEST).o $(DLIBCRYPTO)
	@target=$(EVPEXTRATEST); $(BUILD_CMD)

$(P5_CRPT2_TEST)$(EXE_EXT): $(P5_CRPT2_TEST).o $(DLIBCRYPTO)
	@target=$(P5_CRPT2_TEST); $(BUILD_CMD)

$(ECDSATEST)$(EXE_EXT): $(ECDSATEST).o $(DLIBCRYPTO)
	@target=$(ECDSATEST); $(BUILD_CMD)

$(ECDHTEST)$(EXE_EXT): $(ECDHTEST).o $(DLIBCRYPTO)
	@target=$(ECDHTEST); $(BUILD_CMD)

$(IGETEST)$(EXE_EXT): $(IGETEST).o $(DLIBCRYPTO)
	@target=$(IGETEST); $(BUILD_CMD)

$(JPAKETEST)$(EXE_EXT): $(JPAKETEST).o $(DLIBCRYPTO)
	@target=$(JPAKETEST); $(BUILD_CMD)

$(SECMEMTEST)$(EXE_EXT): $(SECMEMTEST).o $(DLIBCRYPTO)
	@target=$(SECMEMTEST); $(BUILD_CMD)

$(SRPTEST)$(EXE_EXT): $(SRPTEST).o $(DLIBCRYPTO)
	@target=$(SRPTEST); $(BUILD_CMD)

$(V3NAMETEST)$(EXE_EXT): $(V3NAMETEST).o $(DLIBCRYPTO)
	@target=$(V3NAMETEST); $(BUILD_CMD)

$(HEARTBEATTEST)$(EXE_EXT): $(HEARTBEATTEST).o $(DLIBCRYPTO) testutil.o
	@target=$(HEARTBEATTEST) testutil=testutil.o; $(BUILD_CMD_STATIC)

$(CONSTTIMETEST)$(EXE_EXT): $(CONSTTIMETEST).o
	@target=$(CONSTTIMETEST) $(BUILD_CMD)

$(VERIFYEXTRATEST)$(EXE_EXT): $(VERIFYEXTRATEST).o
	@target=$(VERIFYEXTRATEST) $(BUILD_CMD)

$(CLIENTHELLOTEST)$(EXE_EXT): $(CLIENTHELLOTEST).o
	@target=$(CLIENTHELLOTEST) $(BUILD_CMD)

$(PACKETTEST)$(EXE_EXT): $(PACKETTEST).o
	@target=$(PACKETTEST) $(BUILD_CMD)

$(ASYNCTEST)$(EXE_EXT): $(ASYNCTEST).o
	@target=$(ASYNCTEST) $(BUILD_CMD)

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

asynctest.o: ../e_os.h ../include/../apps/apps.h ../include/../apps/progs.h
asynctest.o: ../include/openssl/asn1.h ../include/openssl/async.h
asynctest.o: ../include/openssl/bio.h ../include/openssl/buffer.h
asynctest.o: ../include/openssl/conf.h ../include/openssl/crypto.h
asynctest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
asynctest.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
asynctest.o: ../include/openssl/engine.h ../include/openssl/evp.h
asynctest.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
asynctest.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
asynctest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
asynctest.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
asynctest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
asynctest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
asynctest.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
asynctest.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
asynctest.o: asynctest.c
bftest.o: ../e_os.h ../include/openssl/blowfish.h ../include/openssl/e_os2.h
bftest.o: ../include/openssl/opensslconf.h bftest.c
bntest.o: ../crypto/bn/bn_lcl.h ../crypto/include/internal/bn_int.h ../e_os.h
bntest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
bntest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
bntest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
bntest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
bntest.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
bntest.o: ../include/openssl/evp.h ../include/openssl/lhash.h
bntest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
bntest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
bntest.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
bntest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
bntest.o: ../include/openssl/sha.h ../include/openssl/stack.h
bntest.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
bntest.o: ../include/openssl/x509_vfy.h bntest.c
casttest.o: ../e_os.h ../include/openssl/cast.h ../include/openssl/e_os2.h
casttest.o: ../include/openssl/opensslconf.h casttest.c
clienthellotest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
clienthellotest.o: ../include/openssl/buffer.h ../include/openssl/comp.h
clienthellotest.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
clienthellotest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
clienthellotest.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
clienthellotest.o: ../include/openssl/err.h ../include/openssl/evp.h
clienthellotest.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
clienthellotest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
clienthellotest.o: ../include/openssl/opensslconf.h
clienthellotest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
clienthellotest.o: ../include/openssl/pem.h ../include/openssl/pem2.h
clienthellotest.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
clienthellotest.o: ../include/openssl/sha.h ../include/openssl/srtp.h
clienthellotest.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
clienthellotest.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
clienthellotest.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
clienthellotest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
clienthellotest.o: clienthellotest.c
constant_time_test.o: ../e_os.h ../include/internal/constant_time_locl.h
constant_time_test.o: ../include/openssl/e_os2.h
constant_time_test.o: ../include/openssl/opensslconf.h constant_time_test.c
destest.o: ../include/openssl/des.h ../include/openssl/e_os2.h
destest.o: ../include/openssl/opensslconf.h destest.c
dhtest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
dhtest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
dhtest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
dhtest.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
dhtest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dhtest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
dhtest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h dhtest.c
dsatest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
dsatest.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
dsatest.o: ../include/openssl/e_os2.h ../include/openssl/err.h
dsatest.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
dsatest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsatest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
dsatest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h dsatest.c
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
evp_extra_test.o: ../include/openssl/asn1.h ../include/openssl/bio.h
evp_extra_test.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
evp_extra_test.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
evp_extra_test.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
evp_extra_test.o: ../include/openssl/err.h ../include/openssl/evp.h
evp_extra_test.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
evp_extra_test.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
evp_extra_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
evp_extra_test.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
evp_extra_test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
evp_extra_test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
evp_extra_test.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
evp_extra_test.o: evp_extra_test.c
evp_test.o: ../include/internal/numbers.h ../include/openssl/asn1.h
evp_test.o: ../include/openssl/bio.h ../include/openssl/buffer.h
evp_test.o: ../include/openssl/conf.h ../include/openssl/crypto.h
evp_test.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
evp_test.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
evp_test.o: ../include/openssl/err.h ../include/openssl/evp.h
evp_test.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
evp_test.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
evp_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
evp_test.o: ../include/openssl/pem.h ../include/openssl/pem2.h
evp_test.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
evp_test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
evp_test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
evp_test.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
evp_test.o: ../include/openssl/x509v3.h evp_test.c
exptest.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/bn.h
exptest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
exptest.o: ../include/openssl/err.h ../include/openssl/lhash.h
exptest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
exptest.o: ../include/openssl/ossl_typ.h ../include/openssl/rand.h
exptest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
exptest.o: ../include/openssl/symhacks.h exptest.c
gmdifftest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
gmdifftest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gmdifftest.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
gmdifftest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gmdifftest.o: gmdifftest.c
gost2814789test.o: ../e_os.h ../engines/ccgost/gost89.h
gost2814789test.o: ../include/openssl/asn1.h ../include/openssl/bio.h
gost2814789test.o: ../include/openssl/buffer.h ../include/openssl/conf.h
gost2814789test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
gost2814789test.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gost2814789test.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
gost2814789test.o: ../include/openssl/err.h ../include/openssl/evp.h
gost2814789test.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
gost2814789test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gost2814789test.o: ../include/openssl/opensslconf.h
gost2814789test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gost2814789test.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
gost2814789test.o: ../include/openssl/sha.h ../include/openssl/stack.h
gost2814789test.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
gost2814789test.o: ../include/openssl/x509_vfy.h gost2814789test.c
heartbeat_test.o: ../e_os.h ../include/openssl/asn1.h
heartbeat_test.o: ../include/openssl/async.h ../include/openssl/bio.h
heartbeat_test.o: ../include/openssl/bn.h ../include/openssl/buffer.h
heartbeat_test.o: ../include/openssl/comp.h ../include/openssl/crypto.h
heartbeat_test.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
heartbeat_test.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
heartbeat_test.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
heartbeat_test.o: ../include/openssl/err.h ../include/openssl/evp.h
heartbeat_test.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
heartbeat_test.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
heartbeat_test.o: ../include/openssl/opensslconf.h
heartbeat_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
heartbeat_test.o: ../include/openssl/pem.h ../include/openssl/pem2.h
heartbeat_test.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
heartbeat_test.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
heartbeat_test.o: ../include/openssl/sha.h ../include/openssl/srtp.h
heartbeat_test.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
heartbeat_test.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
heartbeat_test.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
heartbeat_test.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
heartbeat_test.o: ../ssl/packet_locl.h ../ssl/record/record.h ../ssl/ssl_locl.h
heartbeat_test.o: ../ssl/statem/statem.h heartbeat_test.c testutil.h
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
igetest.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/crypto.h
igetest.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
igetest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
igetest.o: ../include/openssl/rand.h ../include/openssl/safestack.h
igetest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h igetest.c
jpaketest.o: ../include/openssl/opensslconf.h jpaketest.c
md2test.o: ../e_os.h ../include/openssl/e_os2.h
md2test.o: ../include/openssl/opensslconf.h md2test.c
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
mdc2test.o: ../include/openssl/e_os2.h ../include/openssl/evp.h
mdc2test.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
mdc2test.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
mdc2test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
mdc2test.o: ../include/openssl/safestack.h ../include/openssl/stack.h
mdc2test.o: ../include/openssl/symhacks.h mdc2test.c
nptest.o: nptest.c
p5_crpt2_test.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
p5_crpt2_test.o: ../include/openssl/buffer.h ../include/openssl/conf.h
p5_crpt2_test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
p5_crpt2_test.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
p5_crpt2_test.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
p5_crpt2_test.o: ../include/openssl/err.h ../include/openssl/evp.h
p5_crpt2_test.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
p5_crpt2_test.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
p5_crpt2_test.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
p5_crpt2_test.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
p5_crpt2_test.o: ../include/openssl/sha.h ../include/openssl/stack.h
p5_crpt2_test.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
p5_crpt2_test.o: ../include/openssl/x509_vfy.h p5_crpt2_test.c
packettest.o: ../e_os.h ../include/openssl/bn.h ../include/openssl/buffer.h
packettest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
packettest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
packettest.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
packettest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
packettest.o: ../ssl/packet_locl.h packettest.c
pbelutest.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pbelutest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pbelutest.o: ../include/openssl/evp.h ../include/openssl/obj_mac.h
pbelutest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pbelutest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pbelutest.o: ../include/openssl/safestack.h ../include/openssl/stack.h
pbelutest.o: ../include/openssl/symhacks.h pbelutest.c
randtest.o: ../e_os.h ../include/openssl/e_os2.h
randtest.o: ../include/openssl/opensslconf.h ../include/openssl/ossl_typ.h
randtest.o: ../include/openssl/rand.h randtest.c
rc2test.o: ../e_os.h ../include/openssl/e_os2.h
rc2test.o: ../include/openssl/opensslconf.h ../include/openssl/rc2.h rc2test.c
rc4test.o: ../e_os.h ../include/openssl/e_os2.h
rc4test.o: ../include/openssl/opensslconf.h ../include/openssl/rc4.h
rc4test.o: ../include/openssl/sha.h rc4test.c
rc5test.o: ../e_os.h ../include/openssl/e_os2.h
rc5test.o: ../include/openssl/opensslconf.h rc5test.c
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
ssltest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/async.h
ssltest.o: ../include/openssl/bio.h ../include/openssl/bn.h
ssltest.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssltest.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ssltest.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ssltest.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssltest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssltest.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ssltest.o: ../include/openssl/err.h ../include/openssl/evp.h
ssltest.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssltest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssltest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssltest.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssltest.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssltest.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
ssltest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssltest.o: ../include/openssl/sha.h ../include/openssl/srp.h
ssltest.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssltest.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssltest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssltest.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssltest.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
ssltest.o: ../ssl/packet_locl.h ../ssl/record/record.h ../ssl/ssl_locl.h
ssltest.o: ../ssl/statem/statem.h ssltest.c
testutil.o: ../e_os.h ../include/openssl/e_os2.h
testutil.o: ../include/openssl/opensslconf.h testutil.c testutil.h
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
verify_extra_test.o: ../include/openssl/asn1.h ../include/openssl/bio.h
verify_extra_test.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
verify_extra_test.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
verify_extra_test.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
verify_extra_test.o: ../include/openssl/err.h ../include/openssl/evp.h
verify_extra_test.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
verify_extra_test.o: ../include/openssl/objects.h
verify_extra_test.o: ../include/openssl/opensslconf.h
verify_extra_test.o: ../include/openssl/opensslv.h
verify_extra_test.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
verify_extra_test.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify_extra_test.o: ../include/openssl/safestack.h ../include/openssl/sha.h
verify_extra_test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
verify_extra_test.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
verify_extra_test.o: verify_extra_test.c
wp_test.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
wp_test.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
wp_test.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
wp_test.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
wp_test.o: ../include/openssl/whrlpool.h wp_test.c
