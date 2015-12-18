#
# OpenSSL/crypto/engine/Makefile
#

DIR=	engine
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= eng_err.c eng_lib.c eng_list.c eng_init.c eng_ctrl.c \
	eng_table.c eng_pkey.c eng_fat.c eng_all.c \
	tb_rsa.c tb_dsa.c tb_dh.c tb_rand.c tb_store.c \
	tb_cipher.c tb_digest.c tb_pkmeth.c tb_asnmth.c tb_eckey.c \
	eng_openssl.c eng_cnf.c eng_dyn.c eng_cryptodev.c \
	eng_rdrand.c
LIBOBJ= eng_err.o eng_lib.o eng_list.o eng_init.o eng_ctrl.o \
	eng_table.o eng_pkey.o eng_fat.o eng_all.o \
	tb_rsa.o tb_dsa.o tb_dh.o tb_rand.o tb_store.o \
	tb_cipher.o tb_digest.o tb_pkmeth.o tb_asnmth.o tb_eckey.o \
	eng_openssl.o eng_cnf.o eng_dyn.o eng_cryptodev.o \
	eng_rdrand.o

SRC= $(LIBSRC)

HEADER=	

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

eng_all.o: ../../e_os.h ../../include/openssl/asn1.h
eng_all.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_all.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_all.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_all.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_all.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_all.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_all.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_all.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
eng_all.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
eng_all.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_all.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
eng_all.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_all.o: ../../include/openssl/ui.h ../../include/openssl/x509.h
eng_all.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
eng_all.o: eng_all.c eng_int.h
eng_cnf.o: ../../e_os.h ../../include/openssl/asn1.h
eng_cnf.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_cnf.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
eng_cnf.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_cnf.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_cnf.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
eng_cnf.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_cnf.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_cnf.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
eng_cnf.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_cnf.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_cnf.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_cnf.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_cnf.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_cnf.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_cnf.o: ../include/internal/cryptlib.h eng_cnf.c eng_int.h
eng_cryptodev.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_cryptodev.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
eng_cryptodev.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_cryptodev.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_cryptodev.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
eng_cryptodev.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_cryptodev.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_cryptodev.o: ../../include/openssl/objects.h
eng_cryptodev.o: ../../include/openssl/opensslconf.h
eng_cryptodev.o: ../../include/openssl/opensslv.h
eng_cryptodev.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
eng_cryptodev.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_cryptodev.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
eng_cryptodev.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_cryptodev.o: ../../include/openssl/ui.h ../../include/openssl/x509.h
eng_cryptodev.o: ../../include/openssl/x509_vfy.h eng_cryptodev.c
eng_ctrl.o: ../../e_os.h ../../include/openssl/asn1.h
eng_ctrl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_ctrl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_ctrl.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_ctrl.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_ctrl.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_ctrl.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_ctrl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_ctrl.o: ../../include/openssl/opensslconf.h
eng_ctrl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_ctrl.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_ctrl.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_ctrl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_ctrl.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_ctrl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_ctrl.o: ../include/internal/cryptlib.h eng_ctrl.c eng_int.h
eng_dyn.o: ../../e_os.h ../../include/openssl/asn1.h
eng_dyn.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_dyn.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_dyn.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_dyn.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
eng_dyn.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
eng_dyn.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_dyn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_dyn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
eng_dyn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_dyn.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_dyn.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_dyn.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_dyn.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_dyn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_dyn.o: ../include/internal/cryptlib.h eng_dyn.c eng_int.h
eng_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_err.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
eng_err.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_err.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_err.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
eng_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
eng_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_err.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_err.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_err.o: eng_err.c
eng_fat.o: ../../e_os.h ../../include/openssl/asn1.h
eng_fat.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_fat.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
eng_fat.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_fat.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_fat.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
eng_fat.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_fat.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_fat.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
eng_fat.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_fat.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_fat.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_fat.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_fat.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_fat.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_fat.o: ../include/internal/cryptlib.h eng_fat.c eng_int.h
eng_init.o: ../../e_os.h ../../include/openssl/asn1.h
eng_init.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_init.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_init.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_init.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_init.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_init.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_init.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_init.o: ../../include/openssl/opensslconf.h
eng_init.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_init.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_init.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_init.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_init.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_init.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_init.o: ../include/internal/cryptlib.h eng_init.c eng_int.h
eng_lib.o: ../../e_os.h ../../include/openssl/asn1.h
eng_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
eng_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
eng_lib.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
eng_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_lib.o: ../../include/openssl/ui.h ../../include/openssl/x509.h
eng_lib.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
eng_lib.o: eng_int.h eng_lib.c
eng_list.o: ../../e_os.h ../../include/openssl/asn1.h
eng_list.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_list.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_list.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_list.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_list.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_list.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_list.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_list.o: ../../include/openssl/opensslconf.h
eng_list.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_list.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_list.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_list.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_list.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_list.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_list.o: ../include/internal/cryptlib.h eng_int.h eng_list.c
eng_openssl.o: ../../e_os.h ../../include/openssl/asn1.h
eng_openssl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_openssl.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
eng_openssl.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_openssl.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
eng_openssl.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_openssl.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_openssl.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
eng_openssl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_openssl.o: ../../include/openssl/objects.h
eng_openssl.o: ../../include/openssl/opensslconf.h
eng_openssl.o: ../../include/openssl/opensslv.h
eng_openssl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
eng_openssl.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
eng_openssl.o: ../../include/openssl/rand.h ../../include/openssl/rc4.h
eng_openssl.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_openssl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_openssl.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_openssl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_openssl.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
eng_openssl.o: eng_openssl.c
eng_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
eng_pkey.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_pkey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_pkey.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_pkey.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_pkey.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_pkey.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_pkey.o: ../../include/openssl/opensslconf.h
eng_pkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_pkey.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_pkey.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_pkey.o: ../include/internal/cryptlib.h eng_int.h eng_pkey.c
eng_rdrand.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_rdrand.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
eng_rdrand.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_rdrand.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_rdrand.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
eng_rdrand.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_rdrand.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_rdrand.o: ../../include/openssl/objects.h
eng_rdrand.o: ../../include/openssl/opensslconf.h
eng_rdrand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_rdrand.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_rdrand.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_rdrand.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_rdrand.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_rdrand.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_rdrand.o: eng_rdrand.c
eng_table.o: ../../e_os.h ../../include/openssl/asn1.h
eng_table.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_table.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_table.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_table.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
eng_table.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_table.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
eng_table.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_table.o: ../../include/openssl/opensslconf.h
eng_table.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_table.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_table.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_table.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
eng_table.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_table.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_table.o: ../include/internal/cryptlib.h eng_int.h eng_table.c
tb_asnmth.o: ../../e_os.h ../../include/openssl/asn1.h
tb_asnmth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_asnmth.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_asnmth.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_asnmth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_asnmth.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_asnmth.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_asnmth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_asnmth.o: ../../include/openssl/opensslconf.h
tb_asnmth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_asnmth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_asnmth.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_asnmth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_asnmth.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_asnmth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_asnmth.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
tb_asnmth.o: eng_int.h tb_asnmth.c
tb_cipher.o: ../../e_os.h ../../include/openssl/asn1.h
tb_cipher.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_cipher.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_cipher.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_cipher.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_cipher.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_cipher.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_cipher.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_cipher.o: ../../include/openssl/opensslconf.h
tb_cipher.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_cipher.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_cipher.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_cipher.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_cipher.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_cipher.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_cipher.o: ../include/internal/cryptlib.h eng_int.h tb_cipher.c
tb_dh.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
tb_dh.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tb_dh.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
tb_dh.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_dh.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
tb_dh.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tb_dh.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tb_dh.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_dh.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_dh.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_dh.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_dh.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_dh.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_dh.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_dh.o: ../include/internal/cryptlib.h eng_int.h tb_dh.c
tb_digest.o: ../../e_os.h ../../include/openssl/asn1.h
tb_digest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_digest.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_digest.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_digest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_digest.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_digest.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_digest.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_digest.o: ../../include/openssl/opensslconf.h
tb_digest.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_digest.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_digest.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_digest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_digest.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_digest.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_digest.o: ../include/internal/cryptlib.h eng_int.h tb_digest.c
tb_dsa.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
tb_dsa.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tb_dsa.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
tb_dsa.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_dsa.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
tb_dsa.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tb_dsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tb_dsa.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_dsa.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_dsa.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_dsa.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_dsa.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_dsa.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_dsa.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_dsa.o: ../include/internal/cryptlib.h eng_int.h tb_dsa.c
tb_eckey.o: ../../e_os.h ../../include/openssl/asn1.h
tb_eckey.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_eckey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_eckey.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_eckey.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_eckey.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_eckey.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_eckey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_eckey.o: ../../include/openssl/opensslconf.h
tb_eckey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_eckey.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_eckey.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_eckey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_eckey.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_eckey.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_eckey.o: ../include/internal/cryptlib.h eng_int.h tb_eckey.c
tb_pkmeth.o: ../../e_os.h ../../include/openssl/asn1.h
tb_pkmeth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_pkmeth.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_pkmeth.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_pkmeth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_pkmeth.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_pkmeth.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_pkmeth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_pkmeth.o: ../../include/openssl/opensslconf.h
tb_pkmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_pkmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_pkmeth.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_pkmeth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_pkmeth.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_pkmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_pkmeth.o: ../include/internal/cryptlib.h eng_int.h tb_pkmeth.c
tb_rand.o: ../../e_os.h ../../include/openssl/asn1.h
tb_rand.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_rand.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_rand.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_rand.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_rand.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_rand.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_rand.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_rand.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
tb_rand.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
tb_rand.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
tb_rand.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_rand.o: ../../include/openssl/ui.h ../../include/openssl/x509.h
tb_rand.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
tb_rand.o: eng_int.h tb_rand.c
tb_rsa.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
tb_rsa.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tb_rsa.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
tb_rsa.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_rsa.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
tb_rsa.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tb_rsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tb_rsa.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_rsa.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_rsa.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_rsa.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_rsa.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_rsa.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_rsa.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_rsa.o: ../include/internal/cryptlib.h eng_int.h tb_rsa.c
tb_store.o: ../../e_os.h ../../include/openssl/asn1.h
tb_store.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tb_store.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tb_store.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tb_store.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tb_store.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_store.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tb_store.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_store.o: ../../include/openssl/opensslconf.h
tb_store.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_store.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
tb_store.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
tb_store.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tb_store.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
tb_store.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_store.o: ../include/internal/cryptlib.h eng_int.h tb_store.c
