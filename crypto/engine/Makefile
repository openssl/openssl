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
TEST= enginetest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= eng_err.c eng_lib.c eng_list.c eng_init.c eng_ctrl.c \
	eng_table.c eng_pkey.c eng_fat.c eng_all.c \
	tb_rsa.c tb_dsa.c tb_ecdsa.c tb_dh.c tb_ecdh.c tb_rand.c tb_store.c \
	tb_cipher.c tb_digest.c tb_pkmeth.c tb_asnmth.c \
	eng_openssl.c eng_cnf.c eng_dyn.c eng_cryptodev.c \
	eng_rsax.c eng_rdrand.c
LIBOBJ= eng_err.o eng_lib.o eng_list.o eng_init.o eng_ctrl.o \
	eng_table.o eng_pkey.o eng_fat.o eng_all.o \
	tb_rsa.o tb_dsa.o tb_ecdsa.o tb_dh.o tb_ecdh.o tb_rand.o tb_store.o \
	tb_cipher.o tb_digest.o tb_pkmeth.o tb_asnmth.o \
	eng_openssl.o eng_cnf.o eng_dyn.o eng_cryptodev.o \
	eng_rsax.o eng_rdrand.o

SRC= $(LIBSRC)

EXHEADER= engine.h
HEADER=	$(EXHEADER)

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

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
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
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

eng_all.o: ../../e_os.h ../../include/openssl/asn1.h
eng_all.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_all.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_all.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_all.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
eng_all.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_all.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_all.c eng_int.h
eng_cnf.o: ../../e_os.h ../../include/openssl/asn1.h
eng_cnf.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
eng_cnf.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_cnf.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_cnf.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_cnf.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_cnf.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_cnf.o: ../cryptlib.h eng_cnf.c eng_int.h
eng_cryptodev.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_cryptodev.o: ../../include/openssl/engine.h ../../include/openssl/lhash.h
eng_cryptodev.o: ../../include/openssl/obj_mac.h
eng_cryptodev.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_cryptodev.o: ../../include/openssl/safestack.h
eng_cryptodev.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_cryptodev.o: ../../include/openssl/x509_vfy.h eng_cryptodev.c
eng_ctrl.o: ../../e_os.h ../../include/openssl/asn1.h
eng_ctrl.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_ctrl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_ctrl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_ctrl.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
eng_ctrl.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_ctrl.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_ctrl.c eng_int.h
eng_dyn.o: ../../e_os.h ../../include/openssl/asn1.h
eng_dyn.o: ../../include/openssl/bio.h ../../include/openssl/dso.h
eng_dyn.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_dyn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_dyn.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_dyn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_dyn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_dyn.o: ../cryptlib.h eng_dyn.c eng_int.h
eng_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_err.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_err.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_err.o: eng_err.c
eng_fat.o: ../../e_os.h ../../include/openssl/asn1.h
eng_fat.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
eng_fat.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_fat.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_fat.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_fat.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_fat.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_fat.o: ../cryptlib.h eng_fat.c eng_int.h
eng_init.o: ../../e_os.h ../../include/openssl/asn1.h
eng_init.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_init.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_init.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_init.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
eng_init.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_init.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_init.c eng_int.h
eng_lib.o: ../../e_os.h ../../include/openssl/asn1.h
eng_lib.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
eng_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_lib.o: ../cryptlib.h eng_int.h eng_lib.c
eng_list.o: ../../e_os.h ../../include/openssl/asn1.h
eng_list.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_list.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_list.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_list.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
eng_list.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_list.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h eng_list.c
eng_openssl.o: ../../e_os.h ../../include/openssl/asn1.h
eng_openssl.o: ../../include/openssl/bio.h ../../include/openssl/dso.h
eng_openssl.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_openssl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_openssl.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
eng_openssl.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
eng_openssl.o: ../../include/openssl/rand.h ../../include/openssl/rc4.h
eng_openssl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_openssl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_openssl.o: ../cryptlib.h eng_openssl.c
eng_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
eng_pkey.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
eng_pkey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_pkey.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h eng_pkey.c
eng_rdrand.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_rdrand.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_rdrand.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_rdrand.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_rdrand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
eng_rdrand.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_rdrand.o: ../../include/openssl/x509_vfy.h eng_rdrand.c
eng_rsax.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_rsax.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_rsax.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
eng_rsax.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
eng_rsax.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_rsax.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_rsax.o: eng_rsax.c
eng_table.o: ../../e_os.h ../../include/openssl/asn1.h
eng_table.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
eng_table.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_table.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_table.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
eng_table.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
eng_table.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h
eng_table.o: eng_table.c
tb_asnmth.o: ../../e_os.h ../../include/openssl/asn1.h
tb_asnmth.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_asnmth.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_asnmth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_asnmth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_asnmth.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_asnmth.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
tb_asnmth.o: eng_int.h tb_asnmth.c
tb_cipher.o: ../../e_os.h ../../include/openssl/asn1.h
tb_cipher.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_cipher.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_cipher.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_cipher.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_cipher.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_cipher.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h
tb_cipher.o: tb_cipher.c
tb_dh.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
tb_dh.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_dh.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tb_dh.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
tb_dh.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tb_dh.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_dh.o: ../cryptlib.h eng_int.h tb_dh.c
tb_digest.o: ../../e_os.h ../../include/openssl/asn1.h
tb_digest.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_digest.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_digest.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_digest.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_digest.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_digest.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h
tb_digest.o: tb_digest.c
tb_dsa.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
tb_dsa.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_dsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tb_dsa.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
tb_dsa.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tb_dsa.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_dsa.o: ../cryptlib.h eng_int.h tb_dsa.c
tb_ecdh.o: ../../e_os.h ../../include/openssl/asn1.h
tb_ecdh.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_ecdh.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_ecdh.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_ecdh.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_ecdh.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_ecdh.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h tb_ecdh.c
tb_ecdsa.o: ../../e_os.h ../../include/openssl/asn1.h
tb_ecdsa.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_ecdsa.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_ecdsa.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_ecdsa.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_ecdsa.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_ecdsa.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h tb_ecdsa.c
tb_pkmeth.o: ../../e_os.h ../../include/openssl/asn1.h
tb_pkmeth.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_pkmeth.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_pkmeth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_pkmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_pkmeth.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_pkmeth.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h
tb_pkmeth.o: tb_pkmeth.c
tb_rand.o: ../../e_os.h ../../include/openssl/asn1.h
tb_rand.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_rand.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_rand.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_rand.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_rand.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_rand.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h tb_rand.c
tb_rsa.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
tb_rsa.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_rsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tb_rsa.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
tb_rsa.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tb_rsa.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tb_rsa.o: ../cryptlib.h eng_int.h tb_rsa.c
tb_store.o: ../../e_os.h ../../include/openssl/asn1.h
tb_store.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
tb_store.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tb_store.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tb_store.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tb_store.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
tb_store.o: ../../include/openssl/x509_vfy.h ../cryptlib.h eng_int.h tb_store.c
