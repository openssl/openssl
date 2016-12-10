#
# OpenSSL/fips-1.0/dsa/Makefile
#

DIR=	dsa
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
TEST=fips_dsatest.c fips_dssvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_dsa_ossl.c fips_dsa_gen.c fips_dsa_selftest.c
LIBOBJ=fips_dsa_ossl.o fips_dsa_gen.o fips_dsa_selftest.o

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
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

Q=../testvectors/dsa/req
A=../testvectors/dsa/rsp

fips_test:
	-rm -rf $A
	mkdir $A
	if [ -f $(Q)/PQGGen.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs pqg < $(Q)/PQGGen.req > $(A)/PQGGen.rsp; fi
	if [ -f $(Q)/KeyPair.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs keypair < $(Q)/KeyPair.req > $(A)/KeyPair.rsp; fi
	if [ -f $(Q)/SigGen.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs siggen < $(Q)/SigGen.req > $(A)/SigGen.rsp; fi
	if [ -f $(Q)/SigVer.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs sigver < $Q/SigVer.req > $A/SigVer.rsp; fi

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

fips_dsa_gen.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_dsa_gen.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
fips_dsa_gen.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
fips_dsa_gen.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_dsa_gen.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_dsa_gen.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_dsa_gen.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_dsa_gen.o: ../../include/openssl/fips.h ../../include/openssl/fips_sha.h
fips_dsa_gen.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
fips_dsa_gen.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
fips_dsa_gen.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
fips_dsa_gen.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_dsa_gen.o: ../../include/openssl/opensslconf.h
fips_dsa_gen.o: ../../include/openssl/opensslv.h
fips_dsa_gen.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_dsa_gen.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_dsa_gen.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
fips_dsa_gen.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_dsa_gen.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_dsa_gen.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_dsa_gen.o: ../../include/openssl/ui_compat.h fips_dsa_gen.c
fips_dsa_ossl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_dsa_ossl.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_dsa_ossl.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
fips_dsa_ossl.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
fips_dsa_ossl.o: ../../include/openssl/err.h ../../include/openssl/fips.h
fips_dsa_ossl.o: ../../include/openssl/lhash.h
fips_dsa_ossl.o: ../../include/openssl/opensslconf.h
fips_dsa_ossl.o: ../../include/openssl/opensslv.h
fips_dsa_ossl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_dsa_ossl.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_dsa_ossl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_dsa_ossl.o: ../../include/openssl/ui.h fips_dsa_ossl.c
fips_dsa_selftest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_dsa_selftest.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
fips_dsa_selftest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_dsa_selftest.o: ../../include/openssl/err.h ../../include/openssl/fips.h
fips_dsa_selftest.o: ../../include/openssl/lhash.h
fips_dsa_selftest.o: ../../include/openssl/opensslconf.h
fips_dsa_selftest.o: ../../include/openssl/opensslv.h
fips_dsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_dsa_selftest.o: ../../include/openssl/safestack.h
fips_dsa_selftest.o: ../../include/openssl/stack.h
fips_dsa_selftest.o: ../../include/openssl/symhacks.h fips_dsa_selftest.c
fips_dsatest.o: ../../e_os.h ../../include/openssl/asn1.h
fips_dsatest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_dsatest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_dsatest.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_dsatest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_dsatest.o: ../../include/openssl/engine.h ../../include/openssl/err.h
fips_dsatest.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_dsatest.o: ../../include/openssl/lhash.h
fips_dsatest.o: ../../include/openssl/opensslconf.h
fips_dsatest.o: ../../include/openssl/opensslv.h
fips_dsatest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_dsatest.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_dsatest.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_dsatest.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
fips_dsatest.o: fips_dsatest.c
fips_dssvs.o: ../../include/openssl/opensslconf.h fips_dssvs.c
