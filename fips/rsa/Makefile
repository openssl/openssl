#
# SSLeay/fips/rsa/Makefile
#

DIR=	rsa
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_rsavtest.c fips_rsastest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_rsa_eay.c fips_rsa_gen.c fips_rsa_selftest.c
LIBOBJ=fips_rsa_eay.o fips_rsa_gen.o fips_rsa_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@sleep 2; touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

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

top_fips_rsastest:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) TARGET=fips_rsastest sub_target)

top_fips_rsavtest:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) TARGET=fips_rsavtest sub_target)

fips_rsastest: fips_rsastest.o $(TOP)/libcrypto.a
	$(CC) $(CFLAGS) -o fips_rsastest fips_rsastest.o $(PEX_LIBS) $(TOP)/libcrypto.a $(EX_LIBS)
	TOP=$(TOP) $(TOP)/fips/openssl_fips_fingerprint $(TOP)/libcrypto.a fips_rsastest

fips_rsavtest: fips_rsavtest.o $(TOP)/libcrypto.a
	$(CC) $(CFLAGS) -o fips_rsavtest fips_rsavtest.o $(PEX_LIBS) $(TOP)/libcrypto.a $(EX_LIBS)
	TOP=$(TOP) $(TOP)/fips/openssl_fips_fingerprint $(TOP)/libcrypto.a fips_rsavtest

Q=../testvectors/rsa/req
A=../testvectors/rsa/rsp

fips_test: top top_fips_rsastest top_fips_rsavtest
	-rm -rf $(A)
	mkdir $(A)
	./fips_rsastest < $(Q)/SigGen15.req > $(A)/SigGen15.rsp
	./fips_rsavtest < $(Q)/SigVer15.req > $(A)/SigVer15.rsp

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_rsa_eay.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_eay.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_eay.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_eay.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_rsa_eay.o: ../../include/openssl/opensslconf.h
fips_rsa_eay.o: ../../include/openssl/opensslv.h
fips_rsa_eay.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_rsa_eay.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_rsa_eay.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rsa_eay.o: fips_rsa_eay.c
fips_rsa_gen.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_gen.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_gen.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_gen.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_rsa_gen.o: ../../include/openssl/opensslconf.h
fips_rsa_gen.o: ../../include/openssl/opensslv.h
fips_rsa_gen.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rsa.h
fips_rsa_gen.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_rsa_gen.o: ../../include/openssl/symhacks.h fips_rsa_gen.c
fips_rsa_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_selftest.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_selftest.o: ../../include/openssl/fips.h
fips_rsa_selftest.o: ../../include/openssl/fips_sha.h
fips_rsa_selftest.o: ../../include/openssl/lhash.h
fips_rsa_selftest.o: ../../include/openssl/opensslconf.h
fips_rsa_selftest.o: ../../include/openssl/opensslv.h
fips_rsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_rsa_selftest.o: ../../include/openssl/rsa.h
fips_rsa_selftest.o: ../../include/openssl/safestack.h
fips_rsa_selftest.o: ../../include/openssl/stack.h
fips_rsa_selftest.o: ../../include/openssl/symhacks.h fips_rsa_selftest.c
fips_rsastest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_rsastest.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
fips_rsastest.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
fips_rsastest.o: ../../include/openssl/cast.h ../../include/openssl/conf.h
fips_rsastest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_rsastest.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_rsastest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_rsastest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_rsastest.o: ../../include/openssl/hmac.h ../../include/openssl/idea.h
fips_rsastest.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
fips_rsastest.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
fips_rsastest.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
fips_rsastest.o: ../../include/openssl/objects.h
fips_rsastest.o: ../../include/openssl/opensslconf.h
fips_rsastest.o: ../../include/openssl/opensslv.h
fips_rsastest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
fips_rsastest.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_rsastest.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
fips_rsastest.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_rsastest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_rsastest.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_rsastest.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
fips_rsastest.o: ../../include/openssl/x509_vfy.h
fips_rsastest.o: ../../include/openssl/x509v3.h fips_rsastest.c
fips_rsavtest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_rsavtest.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
fips_rsavtest.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
fips_rsavtest.o: ../../include/openssl/cast.h ../../include/openssl/conf.h
fips_rsavtest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_rsavtest.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_rsavtest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_rsavtest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_rsavtest.o: ../../include/openssl/hmac.h ../../include/openssl/idea.h
fips_rsavtest.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
fips_rsavtest.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
fips_rsavtest.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
fips_rsavtest.o: ../../include/openssl/objects.h
fips_rsavtest.o: ../../include/openssl/opensslconf.h
fips_rsavtest.o: ../../include/openssl/opensslv.h
fips_rsavtest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
fips_rsavtest.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_rsavtest.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
fips_rsavtest.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_rsavtest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_rsavtest.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_rsavtest.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
fips_rsavtest.o: ../../include/openssl/x509_vfy.h
fips_rsavtest.o: ../../include/openssl/x509v3.h fips_rsavtest.c
