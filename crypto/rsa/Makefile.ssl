#
# SSLeay/crypto/rsa/Makefile
#

DIR=	rsa
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

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=rsa_test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= rsa_eay.c rsa_gen.c rsa_lib.c rsa_sign.c rsa_saos.c rsa_err.c \
	rsa_pk1.c rsa_ssl.c rsa_none.c rsa_oaep.c rsa_chk.c rsa_null.c
LIBOBJ= rsa_eay.o rsa_gen.o rsa_lib.o rsa_sign.o rsa_saos.o rsa_err.o \
	rsa_pk1.o rsa_ssl.o rsa_none.o rsa_oaep.o rsa_chk.o rsa_null.o

SRC= $(LIBSRC)

EXHEADER= rsa.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

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
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

rsa_chk.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_chk.o: ../../include/openssl/crypto.h ../../include/openssl/err.h
rsa_chk.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
rsa_chk.o: ../../include/openssl/opensslv.h ../../include/openssl/rsa.h
rsa_chk.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_chk.o: ../../include/openssl/symhacks.h
rsa_eay.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_eay.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_eay.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_eay.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_eay.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rsa_eay.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
rsa_eay.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_eay.o: ../../include/openssl/symhacks.h ../cryptlib.h
rsa_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_err.o: ../../include/openssl/crypto.h ../../include/openssl/err.h
rsa_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
rsa_err.o: ../../include/openssl/opensslv.h ../../include/openssl/rsa.h
rsa_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_err.o: ../../include/openssl/symhacks.h
rsa_gen.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_gen.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_gen.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_gen.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_gen.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rsa_gen.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_gen.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rsa_gen.o: ../cryptlib.h
rsa_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_lib.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rsa_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rsa_lib.o: ../cryptlib.h
rsa_none.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_none.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_none.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_none.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_none.o: ../../include/openssl/opensslconf.h
rsa_none.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
rsa_none.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_none.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rsa_none.o: ../cryptlib.h
rsa_null.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_null.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_null.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_null.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_null.o: ../../include/openssl/opensslconf.h
rsa_null.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
rsa_null.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_null.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rsa_null.o: ../cryptlib.h
rsa_oaep.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_oaep.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_oaep.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_oaep.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_oaep.o: ../../include/openssl/opensslconf.h
rsa_oaep.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
rsa_oaep.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_oaep.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rsa_oaep.o: ../../include/openssl/symhacks.h ../cryptlib.h
rsa_pk1.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_pk1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_pk1.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_pk1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_pk1.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rsa_pk1.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
rsa_pk1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_pk1.o: ../../include/openssl/symhacks.h ../cryptlib.h
rsa_saos.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rsa_saos.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
rsa_saos.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
rsa_saos.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
rsa_saos.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
rsa_saos.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_saos.o: ../../include/openssl/err.h ../../include/openssl/evp.h
rsa_saos.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
rsa_saos.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
rsa_saos.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
rsa_saos.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rsa_saos.o: ../../include/openssl/opensslconf.h
rsa_saos.o: ../../include/openssl/opensslv.h ../../include/openssl/pkcs7.h
rsa_saos.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
rsa_saos.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
rsa_saos.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_saos.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rsa_saos.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
rsa_saos.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
rsa_sign.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rsa_sign.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
rsa_sign.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
rsa_sign.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
rsa_sign.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
rsa_sign.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_sign.o: ../../include/openssl/err.h ../../include/openssl/evp.h
rsa_sign.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
rsa_sign.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
rsa_sign.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
rsa_sign.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rsa_sign.o: ../../include/openssl/opensslconf.h
rsa_sign.o: ../../include/openssl/opensslv.h ../../include/openssl/pkcs7.h
rsa_sign.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
rsa_sign.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
rsa_sign.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rsa_sign.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rsa_sign.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
rsa_sign.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
rsa_ssl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rsa_ssl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rsa_ssl.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
rsa_ssl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rsa_ssl.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rsa_ssl.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
rsa_ssl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rsa_ssl.o: ../../include/openssl/symhacks.h ../cryptlib.h
