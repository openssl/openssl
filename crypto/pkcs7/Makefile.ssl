#
# SSLeay/crypto/pkcs7/Makefile
#

DIR=	pkcs7
TOP=	../..
CC=	cc
INCLUDES= -I.. -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
AR=		ar r

PEX_LIBS=
EX_LIBS=
 
CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	pk7_lib.c pkcs7err.c pk7_doit.c pk7_smime.c pk7_attr.c pk7_mime.c
LIBOBJ= pk7_lib.o pkcs7err.o pk7_doit.o pk7_smime.o pk7_attr.o pk7_mime.o

SRC= $(LIBSRC)

EXHEADER=  pkcs7.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:

all:	lib

testapps: enc dec sign verify

enc: enc.o lib
	$(CC) $(CFLAGS) -o enc enc.o $(PEX_LIBS) $(LIB) $(EX_LIBS)

dec: dec.o lib
	$(CC) $(CFLAGS) -o dec dec.o $(PEX_LIBS) $(LIB) $(EX_LIBS)

sign: sign.o lib
	$(CC) $(CFLAGS) -o sign sign.o $(PEX_LIBS) $(LIB) $(EX_LIBS)

verify: verify.o example.o lib
	$(CC) $(CFLAGS) -o verify verify.o $(PEX_LIBS) example.o $(LIB) $(EX_LIBS)

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB)
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff enc dec sign verify

# DO NOT DELETE THIS LINE -- make depend depends on it.

pk7_attr.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk7_attr.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
pk7_attr.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
pk7_attr.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
pk7_attr.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk7_attr.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
pk7_attr.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
pk7_attr.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
pk7_attr.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
pk7_attr.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
pk7_attr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk7_attr.o: ../../include/openssl/opensslv.h ../../include/openssl/pem.h
pk7_attr.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pk7_attr.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
pk7_attr.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
pk7_attr.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
pk7_attr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
pk7_attr.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
pk7_attr.o: ../../include/openssl/x509_vfy.h
pk7_doit.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk7_doit.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
pk7_doit.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
pk7_doit.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
pk7_doit.o: ../../include/openssl/des.h ../../include/openssl/dh.h
pk7_doit.o: ../../include/openssl/dsa.h ../../include/openssl/e_os.h
pk7_doit.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
pk7_doit.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_doit.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
pk7_doit.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
pk7_doit.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
pk7_doit.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_doit.o: ../../include/openssl/opensslconf.h
pk7_doit.o: ../../include/openssl/opensslv.h ../../include/openssl/pkcs7.h
pk7_doit.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
pk7_doit.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
pk7_doit.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
pk7_doit.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_doit.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_doit.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_doit.o: ../../include/openssl/x509v3.h ../cryptlib.h
pk7_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk7_lib.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
pk7_lib.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
pk7_lib.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
pk7_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk7_lib.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
pk7_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_lib.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
pk7_lib.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
pk7_lib.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
pk7_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
pk7_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
pk7_lib.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
pk7_lib.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
pk7_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_lib.o: ../cryptlib.h
pk7_mime.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk7_mime.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
pk7_mime.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
pk7_mime.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
pk7_mime.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk7_mime.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
pk7_mime.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_mime.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
pk7_mime.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
pk7_mime.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
pk7_mime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_mime.o: ../../include/openssl/opensslconf.h
pk7_mime.o: ../../include/openssl/opensslv.h ../../include/openssl/pkcs7.h
pk7_mime.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
pk7_mime.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
pk7_mime.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
pk7_mime.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk7_mime.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk7_mime.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk7_mime.o: ../cryptlib.h
pk7_smime.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk7_smime.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
pk7_smime.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
pk7_smime.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
pk7_smime.o: ../../include/openssl/des.h ../../include/openssl/dh.h
pk7_smime.o: ../../include/openssl/dsa.h ../../include/openssl/e_os.h
pk7_smime.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
pk7_smime.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk7_smime.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
pk7_smime.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
pk7_smime.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
pk7_smime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pk7_smime.o: ../../include/openssl/opensslconf.h
pk7_smime.o: ../../include/openssl/opensslv.h ../../include/openssl/pkcs7.h
pk7_smime.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
pk7_smime.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
pk7_smime.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
pk7_smime.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
pk7_smime.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
pk7_smime.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pk7_smime.o: ../cryptlib.h
pkcs7err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pkcs7err.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
pkcs7err.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
pkcs7err.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
pkcs7err.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pkcs7err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
pkcs7err.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
pkcs7err.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
pkcs7err.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
pkcs7err.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
pkcs7err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pkcs7err.o: ../../include/openssl/opensslv.h ../../include/openssl/pkcs7.h
pkcs7err.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
pkcs7err.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
pkcs7err.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
pkcs7err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
pkcs7err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
pkcs7err.o: ../../include/openssl/x509_vfy.h
