#
# OpenSSL/fips-1.0/hmac/Makefile
#

DIR=	hmac
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
TEST=fips_hmactest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_hmac.c fips_hmac_selftest.c
LIBOBJ=fips_hmac.o fips_hmac_selftest.o

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
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

Q=../testvectors/hmac/req
A=../testvectors/hmac/rsp

fips_test:
	-rm -rf $(A)
	mkdir $(A)
	if [ -f $(Q)/HMAC.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_hmactest < $(Q)/HMAC.req > $(A)/HMAC.rsp; fi

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

fips_hmac.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_hmac.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
fips_hmac.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
fips_hmac.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_hmac.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_hmac.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_hmac.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
fips_hmac.o: ../../include/openssl/idea.h ../../include/openssl/md2.h
fips_hmac.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
fips_hmac.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
fips_hmac.o: ../../include/openssl/objects.h
fips_hmac.o: ../../include/openssl/opensslconf.h
fips_hmac.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_hmac.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_hmac.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
fips_hmac.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_hmac.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_hmac.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_hmac.o: ../../include/openssl/ui_compat.h fips_hmac.c
fips_hmac_selftest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_hmac_selftest.o: ../../include/openssl/bio.h
fips_hmac_selftest.o: ../../include/openssl/blowfish.h
fips_hmac_selftest.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
fips_hmac_selftest.o: ../../include/openssl/crypto.h
fips_hmac_selftest.o: ../../include/openssl/des.h
fips_hmac_selftest.o: ../../include/openssl/des_old.h
fips_hmac_selftest.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
fips_hmac_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_hmac_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_hmac_selftest.o: ../../include/openssl/hmac.h ../../include/openssl/idea.h
fips_hmac_selftest.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
fips_hmac_selftest.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
fips_hmac_selftest.o: ../../include/openssl/mdc2.h
fips_hmac_selftest.o: ../../include/openssl/obj_mac.h
fips_hmac_selftest.o: ../../include/openssl/objects.h
fips_hmac_selftest.o: ../../include/openssl/opensslconf.h
fips_hmac_selftest.o: ../../include/openssl/opensslv.h
fips_hmac_selftest.o: ../../include/openssl/ossl_typ.h
fips_hmac_selftest.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_hmac_selftest.o: ../../include/openssl/rc5.h
fips_hmac_selftest.o: ../../include/openssl/ripemd.h
fips_hmac_selftest.o: ../../include/openssl/rsa.h
fips_hmac_selftest.o: ../../include/openssl/safestack.h
fips_hmac_selftest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_hmac_selftest.o: ../../include/openssl/symhacks.h
fips_hmac_selftest.o: ../../include/openssl/ui.h
fips_hmac_selftest.o: ../../include/openssl/ui_compat.h fips_hmac_selftest.c
fips_hmactest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_hmactest.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
fips_hmactest.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
fips_hmactest.o: ../../include/openssl/cast.h ../../include/openssl/conf.h
fips_hmactest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_hmactest.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_hmactest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_hmactest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_hmactest.o: ../../include/openssl/hmac.h ../../include/openssl/idea.h
fips_hmactest.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
fips_hmactest.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
fips_hmactest.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
fips_hmactest.o: ../../include/openssl/objects.h
fips_hmactest.o: ../../include/openssl/opensslconf.h
fips_hmactest.o: ../../include/openssl/opensslv.h
fips_hmactest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
fips_hmactest.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_hmactest.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
fips_hmactest.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_hmactest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_hmactest.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_hmactest.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
fips_hmactest.o: ../../include/openssl/x509_vfy.h
fips_hmactest.o: ../../include/openssl/x509v3.h fips_hmactest.c
