#
# SSLeay/crypto/pkcs12/Makefile
#

DIR=	pkcs12
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= p12_add.c p12_asn.c p12_attr.c p12_crpt.c p12_crt.c p12_decr.c \
	p12_init.c p12_key.c p12_kiss.c p12_mutl.c\
	p12_utl.c p12_npas.c pk12err.c p12_p8d.c p12_p8e.c
LIBOBJ= p12_add.o p12_asn.o p12_attr.o p12_crpt.o p12_crt.o p12_decr.o \
	p12_init.o p12_key.o p12_kiss.o p12_mutl.o\
	p12_utl.o p12_npas.o pk12err.o p12_p8d.o p12_p8e.o

SRC= $(LIBSRC)

EXHEADER=  pkcs12.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@sh $(TOP)/util/point.sh Makefile.ssl Makefile
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

p12_add.o: ../../e_os.h ../../include/openssl/aes.h
p12_add.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_add.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_add.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_add.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_add.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_add.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_add.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_add.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_add.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_add.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_add.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_add.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_add.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_add.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
p12_add.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_add.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_add.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_add.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_add.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_add.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_add.o: ../cryptlib.h p12_add.c
p12_asn.o: ../../e_os.h ../../include/openssl/aes.h
p12_asn.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
p12_asn.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
p12_asn.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
p12_asn.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
p12_asn.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
p12_asn.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
p12_asn.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
p12_asn.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
p12_asn.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
p12_asn.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
p12_asn.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
p12_asn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_asn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_asn.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_asn.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_asn.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_asn.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_asn.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_asn.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_asn.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_asn.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_asn.c
p12_attr.o: ../../e_os.h ../../include/openssl/aes.h
p12_attr.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_attr.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_attr.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_attr.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_attr.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_attr.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_attr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_attr.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_attr.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_attr.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_attr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_attr.o: ../../include/openssl/opensslconf.h
p12_attr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_attr.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_attr.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_attr.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_attr.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_attr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_attr.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_attr.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_attr.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_attr.c
p12_crpt.o: ../../e_os.h ../../include/openssl/aes.h
p12_crpt.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_crpt.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_crpt.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_crpt.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_crpt.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_crpt.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_crpt.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_crpt.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_crpt.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_crpt.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_crpt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_crpt.o: ../../include/openssl/opensslconf.h
p12_crpt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_crpt.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_crpt.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_crpt.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_crpt.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_crpt.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_crpt.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_crpt.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_crpt.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_crpt.c
p12_crt.o: ../../e_os.h ../../include/openssl/aes.h
p12_crt.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_crt.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_crt.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_crt.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_crt.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_crt.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_crt.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_crt.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_crt.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_crt.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_crt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_crt.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_crt.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_crt.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
p12_crt.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_crt.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_crt.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_crt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_crt.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_crt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_crt.o: ../cryptlib.h p12_crt.c
p12_decr.o: ../../e_os.h ../../include/openssl/aes.h
p12_decr.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_decr.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_decr.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_decr.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_decr.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_decr.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_decr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_decr.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_decr.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_decr.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_decr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_decr.o: ../../include/openssl/opensslconf.h
p12_decr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_decr.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_decr.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_decr.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_decr.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_decr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_decr.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_decr.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_decr.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_decr.c
p12_init.o: ../../e_os.h ../../include/openssl/aes.h
p12_init.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_init.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_init.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_init.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_init.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_init.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_init.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_init.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_init.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_init.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_init.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_init.o: ../../include/openssl/opensslconf.h
p12_init.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_init.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_init.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_init.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_init.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_init.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_init.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_init.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_init.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_init.c
p12_key.o: ../../e_os.h ../../include/openssl/aes.h
p12_key.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_key.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_key.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_key.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_key.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_key.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_key.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_key.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_key.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_key.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_key.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_key.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_key.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
p12_key.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_key.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_key.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_key.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_key.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_key.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_key.o: ../cryptlib.h p12_key.c
p12_kiss.o: ../../e_os.h ../../include/openssl/aes.h
p12_kiss.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_kiss.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_kiss.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_kiss.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_kiss.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_kiss.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_kiss.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_kiss.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_kiss.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_kiss.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_kiss.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_kiss.o: ../../include/openssl/opensslconf.h
p12_kiss.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_kiss.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_kiss.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_kiss.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_kiss.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_kiss.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_kiss.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_kiss.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_kiss.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_kiss.c
p12_mutl.o: ../../e_os.h ../../include/openssl/aes.h
p12_mutl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_mutl.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_mutl.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_mutl.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_mutl.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_mutl.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_mutl.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_mutl.o: ../../include/openssl/hmac.h ../../include/openssl/idea.h
p12_mutl.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
p12_mutl.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
p12_mutl.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
p12_mutl.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_mutl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_mutl.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_mutl.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
p12_mutl.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_mutl.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_mutl.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_mutl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_mutl.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_mutl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_mutl.o: ../cryptlib.h p12_mutl.c
p12_npas.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
p12_npas.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
p12_npas.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
p12_npas.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
p12_npas.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
p12_npas.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
p12_npas.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
p12_npas.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
p12_npas.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
p12_npas.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
p12_npas.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
p12_npas.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_npas.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_npas.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
p12_npas.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_npas.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
p12_npas.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
p12_npas.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p12_npas.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_npas.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
p12_npas.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
p12_npas.o: ../../include/openssl/x509_vfy.h p12_npas.c
p12_p8d.o: ../../e_os.h ../../include/openssl/aes.h
p12_p8d.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_p8d.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_p8d.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_p8d.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_p8d.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_p8d.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_p8d.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_p8d.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_p8d.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_p8d.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_p8d.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_p8d.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_p8d.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_p8d.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
p12_p8d.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_p8d.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_p8d.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_p8d.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_p8d.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_p8d.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_p8d.o: ../cryptlib.h p12_p8d.c
p12_p8e.o: ../../e_os.h ../../include/openssl/aes.h
p12_p8e.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_p8e.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_p8e.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_p8e.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_p8e.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_p8e.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_p8e.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_p8e.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_p8e.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_p8e.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_p8e.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_p8e.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_p8e.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_p8e.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
p12_p8e.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_p8e.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_p8e.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_p8e.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_p8e.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_p8e.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_p8e.o: ../cryptlib.h p12_p8e.c
p12_utl.o: ../../e_os.h ../../include/openssl/aes.h
p12_utl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_utl.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
p12_utl.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
p12_utl.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
p12_utl.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
p12_utl.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p12_utl.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_utl.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
p12_utl.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
p12_utl.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
p12_utl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_utl.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_utl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_utl.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
p12_utl.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
p12_utl.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
p12_utl.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_utl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_utl.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
p12_utl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_utl.o: ../cryptlib.h p12_utl.c
pk12err.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
pk12err.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
pk12err.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
pk12err.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
pk12err.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
pk12err.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
pk12err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
pk12err.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
pk12err.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
pk12err.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
pk12err.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
pk12err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk12err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk12err.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
pk12err.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
pk12err.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
pk12err.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
pk12err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
pk12err.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
pk12err.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
pk12err.o: ../../include/openssl/x509_vfy.h pk12err.c
