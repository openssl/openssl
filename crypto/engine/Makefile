#
# OpenSSL/crypto/engine/Makefile
#

DIR=	engine
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
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
TEST= enginetest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= eng_err.c eng_lib.c eng_list.c eng_init.c eng_ctrl.c \
	eng_table.c eng_pkey.c eng_fat.c eng_all.c \
	tb_rsa.c tb_dsa.c tb_dh.c tb_rand.c tb_cipher.c tb_digest.c \
	eng_openssl.c eng_dyn.c eng_cnf.c \
	hw_atalla.c hw_cswift.c hw_ncipher.c hw_nuron.c hw_ubsec.c \
	hw_cryptodev.c hw_aep.c hw_sureware.c hw_4758_cca.c
LIBOBJ= eng_err.o eng_lib.o eng_list.o eng_init.o eng_ctrl.o \
	eng_table.o eng_pkey.o eng_fat.o eng_all.o \
	tb_rsa.o tb_dsa.o tb_dh.o tb_rand.o tb_cipher.o tb_digest.o \
	eng_openssl.o eng_dyn.o eng_cnf.o \
	hw_atalla.o hw_cswift.o hw_ncipher.o hw_nuron.o hw_ubsec.o \
	hw_cryptodev.o hw_aep.o hw_sureware.o hw_4758_cca.o

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
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

errors:
	$(PERL) $(TOP)/util/mkerr.pl -conf hw.ec \
		-nostatic -staticloader -write hw_*.c

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

eng_all.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_all.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
eng_all.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_all.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_all.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_all.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
eng_all.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
eng_all.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_all.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_all.o: ../../include/openssl/ui.h eng_all.c eng_int.h
eng_cnf.o: ../../e_os.h ../../include/openssl/asn1.h
eng_cnf.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_cnf.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
eng_cnf.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_cnf.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_cnf.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_cnf.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
eng_cnf.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_cnf.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_cnf.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_cnf.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_cnf.o: ../cryptlib.h eng_cnf.c
eng_ctrl.o: ../../e_os.h ../../include/openssl/asn1.h
eng_ctrl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_ctrl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_ctrl.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_ctrl.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_ctrl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_ctrl.o: ../../include/openssl/opensslconf.h
eng_ctrl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_ctrl.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_ctrl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_ctrl.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_ctrl.o: ../cryptlib.h eng_ctrl.c eng_int.h
eng_dyn.o: ../../e_os.h ../../include/openssl/asn1.h
eng_dyn.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_dyn.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_dyn.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_dyn.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
eng_dyn.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_dyn.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
eng_dyn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_dyn.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_dyn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_dyn.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_dyn.o: ../cryptlib.h eng_dyn.c eng_int.h
eng_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_err.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
eng_err.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_err.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
eng_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
eng_err.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_err.o: ../../include/openssl/ui.h eng_err.c
eng_fat.o: ../../e_os.h ../../include/openssl/asn1.h
eng_fat.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_fat.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
eng_fat.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
eng_fat.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_fat.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_fat.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
eng_fat.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_fat.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_fat.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_fat.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_fat.o: ../cryptlib.h eng_fat.c eng_int.h
eng_init.o: ../../e_os.h ../../include/openssl/asn1.h
eng_init.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_init.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_init.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_init.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_init.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_init.o: ../../include/openssl/opensslconf.h
eng_init.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_init.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_init.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_init.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_init.o: ../cryptlib.h eng_init.c eng_int.h
eng_lib.o: ../../e_os.h ../../include/openssl/asn1.h
eng_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
eng_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
eng_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
eng_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_lib.o: ../../include/openssl/ui.h ../cryptlib.h eng_int.h eng_lib.c
eng_list.o: ../../e_os.h ../../include/openssl/asn1.h
eng_list.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_list.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_list.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_list.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_list.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_list.o: ../../include/openssl/opensslconf.h
eng_list.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_list.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_list.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_list.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_list.o: ../cryptlib.h eng_int.h eng_list.c
eng_openssl.o: ../../e_os.h ../../include/openssl/aes.h
eng_openssl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
eng_openssl.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
eng_openssl.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
eng_openssl.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
eng_openssl.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
eng_openssl.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
eng_openssl.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_openssl.o: ../../include/openssl/err.h ../../include/openssl/evp.h
eng_openssl.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
eng_openssl.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
eng_openssl.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
eng_openssl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
eng_openssl.o: ../../include/openssl/opensslconf.h
eng_openssl.o: ../../include/openssl/opensslv.h
eng_openssl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
eng_openssl.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
eng_openssl.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
eng_openssl.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
eng_openssl.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
eng_openssl.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
eng_openssl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_openssl.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
eng_openssl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
eng_openssl.o: ../cryptlib.h eng_openssl.c
eng_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
eng_pkey.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
eng_pkey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
eng_pkey.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
eng_pkey.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
eng_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
eng_pkey.o: ../../include/openssl/opensslconf.h
eng_pkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_pkey.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
eng_pkey.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
eng_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
eng_pkey.o: ../cryptlib.h eng_int.h eng_pkey.c
eng_table.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
eng_table.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
eng_table.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
eng_table.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
eng_table.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
eng_table.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
eng_table.o: ../../include/openssl/engine.h ../../include/openssl/err.h
eng_table.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
eng_table.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
eng_table.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
eng_table.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
eng_table.o: ../../include/openssl/objects.h
eng_table.o: ../../include/openssl/opensslconf.h
eng_table.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
eng_table.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
eng_table.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
eng_table.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
eng_table.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
eng_table.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
eng_table.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
eng_table.o: eng_int.h eng_table.c
hw_4758_cca.o: ../../e_os.h ../../include/openssl/aes.h
hw_4758_cca.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hw_4758_cca.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
hw_4758_cca.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
hw_4758_cca.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
hw_4758_cca.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
hw_4758_cca.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
hw_4758_cca.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
hw_4758_cca.o: ../../include/openssl/err.h ../../include/openssl/evp.h
hw_4758_cca.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
hw_4758_cca.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
hw_4758_cca.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
hw_4758_cca.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
hw_4758_cca.o: ../../include/openssl/opensslconf.h
hw_4758_cca.o: ../../include/openssl/opensslv.h
hw_4758_cca.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
hw_4758_cca.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
hw_4758_cca.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
hw_4758_cca.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
hw_4758_cca.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
hw_4758_cca.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hw_4758_cca.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
hw_4758_cca.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
hw_4758_cca.o: ../cryptlib.h hw_4758_cca.c hw_4758_cca_err.c hw_4758_cca_err.h
hw_4758_cca.o: vendor_defns/hw_4758_cca.h
hw_aep.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hw_aep.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
hw_aep.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
hw_aep.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
hw_aep.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
hw_aep.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
hw_aep.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
hw_aep.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
hw_aep.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
hw_aep.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hw_aep.o: ../../include/openssl/ui.h hw_aep.c hw_aep_err.c hw_aep_err.h
hw_aep.o: vendor_defns/aep.h
hw_atalla.o: ../../e_os.h ../../include/openssl/asn1.h
hw_atalla.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hw_atalla.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
hw_atalla.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
hw_atalla.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
hw_atalla.o: ../../include/openssl/engine.h ../../include/openssl/err.h
hw_atalla.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
hw_atalla.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hw_atalla.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
hw_atalla.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
hw_atalla.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
hw_atalla.o: ../cryptlib.h hw_atalla.c hw_atalla_err.c hw_atalla_err.h
hw_atalla.o: vendor_defns/atalla.h
hw_cryptodev.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
hw_cryptodev.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
hw_cryptodev.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
hw_cryptodev.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
hw_cryptodev.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
hw_cryptodev.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
hw_cryptodev.o: ../../include/openssl/engine.h ../../include/openssl/err.h
hw_cryptodev.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
hw_cryptodev.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
hw_cryptodev.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
hw_cryptodev.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
hw_cryptodev.o: ../../include/openssl/objects.h
hw_cryptodev.o: ../../include/openssl/opensslconf.h
hw_cryptodev.o: ../../include/openssl/opensslv.h
hw_cryptodev.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
hw_cryptodev.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
hw_cryptodev.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
hw_cryptodev.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
hw_cryptodev.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
hw_cryptodev.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
hw_cryptodev.o: ../../include/openssl/ui_compat.h hw_cryptodev.c
hw_cswift.o: ../../e_os.h ../../include/openssl/asn1.h
hw_cswift.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hw_cswift.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
hw_cswift.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
hw_cswift.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
hw_cswift.o: ../../include/openssl/engine.h ../../include/openssl/err.h
hw_cswift.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
hw_cswift.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hw_cswift.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
hw_cswift.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
hw_cswift.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
hw_cswift.o: ../cryptlib.h hw_cswift.c hw_cswift_err.c hw_cswift_err.h
hw_cswift.o: vendor_defns/cswift.h
hw_ncipher.o: ../../e_os.h ../../include/openssl/aes.h
hw_ncipher.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hw_ncipher.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
hw_ncipher.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
hw_ncipher.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
hw_ncipher.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
hw_ncipher.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
hw_ncipher.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
hw_ncipher.o: ../../include/openssl/err.h ../../include/openssl/evp.h
hw_ncipher.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
hw_ncipher.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
hw_ncipher.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
hw_ncipher.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
hw_ncipher.o: ../../include/openssl/opensslconf.h
hw_ncipher.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hw_ncipher.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
hw_ncipher.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
hw_ncipher.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
hw_ncipher.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
hw_ncipher.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
hw_ncipher.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
hw_ncipher.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
hw_ncipher.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
hw_ncipher.o: ../../include/openssl/x509_vfy.h ../cryptlib.h hw_ncipher.c
hw_ncipher.o: hw_ncipher_err.c hw_ncipher_err.h vendor_defns/hwcryptohook.h
hw_nuron.o: ../../e_os.h ../../include/openssl/asn1.h
hw_nuron.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hw_nuron.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
hw_nuron.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
hw_nuron.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
hw_nuron.o: ../../include/openssl/engine.h ../../include/openssl/err.h
hw_nuron.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
hw_nuron.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hw_nuron.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
hw_nuron.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
hw_nuron.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
hw_nuron.o: ../cryptlib.h hw_nuron.c hw_nuron_err.c hw_nuron_err.h
hw_sureware.o: ../../e_os.h ../../include/openssl/aes.h
hw_sureware.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hw_sureware.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
hw_sureware.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
hw_sureware.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
hw_sureware.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
hw_sureware.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
hw_sureware.o: ../../include/openssl/e_os2.h ../../include/openssl/engine.h
hw_sureware.o: ../../include/openssl/err.h ../../include/openssl/evp.h
hw_sureware.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
hw_sureware.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
hw_sureware.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
hw_sureware.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
hw_sureware.o: ../../include/openssl/opensslconf.h
hw_sureware.o: ../../include/openssl/opensslv.h
hw_sureware.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
hw_sureware.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
hw_sureware.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
hw_sureware.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
hw_sureware.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
hw_sureware.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
hw_sureware.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hw_sureware.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
hw_sureware.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
hw_sureware.o: ../cryptlib.h eng_int.h engine.h hw_sureware.c hw_sureware_err.c
hw_sureware.o: hw_sureware_err.h vendor_defns/sureware.h
hw_ubsec.o: ../../e_os.h ../../include/openssl/asn1.h
hw_ubsec.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hw_ubsec.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
hw_ubsec.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
hw_ubsec.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
hw_ubsec.o: ../../include/openssl/engine.h ../../include/openssl/err.h
hw_ubsec.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
hw_ubsec.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hw_ubsec.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
hw_ubsec.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
hw_ubsec.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
hw_ubsec.o: ../cryptlib.h hw_ubsec.c hw_ubsec_err.c hw_ubsec_err.h
hw_ubsec.o: vendor_defns/hw_ubsec.h
tb_cipher.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
tb_cipher.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
tb_cipher.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
tb_cipher.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
tb_cipher.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
tb_cipher.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_cipher.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_cipher.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
tb_cipher.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
tb_cipher.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
tb_cipher.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
tb_cipher.o: ../../include/openssl/objects.h
tb_cipher.o: ../../include/openssl/opensslconf.h
tb_cipher.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_cipher.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
tb_cipher.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
tb_cipher.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
tb_cipher.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_cipher.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_cipher.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
tb_cipher.o: eng_int.h tb_cipher.c
tb_dh.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
tb_dh.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
tb_dh.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
tb_dh.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
tb_dh.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
tb_dh.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_dh.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_dh.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
tb_dh.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
tb_dh.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
tb_dh.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
tb_dh.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_dh.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_dh.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
tb_dh.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
tb_dh.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
tb_dh.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_dh.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_dh.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h eng_int.h
tb_dh.o: tb_dh.c
tb_digest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
tb_digest.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
tb_digest.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
tb_digest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
tb_digest.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
tb_digest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_digest.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_digest.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
tb_digest.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
tb_digest.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
tb_digest.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
tb_digest.o: ../../include/openssl/objects.h
tb_digest.o: ../../include/openssl/opensslconf.h
tb_digest.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_digest.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
tb_digest.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
tb_digest.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
tb_digest.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_digest.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_digest.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
tb_digest.o: eng_int.h tb_digest.c
tb_dsa.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
tb_dsa.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
tb_dsa.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
tb_dsa.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
tb_dsa.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
tb_dsa.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_dsa.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_dsa.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
tb_dsa.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
tb_dsa.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
tb_dsa.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
tb_dsa.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_dsa.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_dsa.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
tb_dsa.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
tb_dsa.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
tb_dsa.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_dsa.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_dsa.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
tb_dsa.o: eng_int.h tb_dsa.c
tb_rand.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
tb_rand.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
tb_rand.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
tb_rand.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
tb_rand.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
tb_rand.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_rand.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_rand.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
tb_rand.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
tb_rand.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
tb_rand.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
tb_rand.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_rand.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
tb_rand.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
tb_rand.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
tb_rand.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_rand.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
tb_rand.o: eng_int.h tb_rand.c
tb_rsa.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
tb_rsa.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
tb_rsa.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
tb_rsa.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
tb_rsa.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
tb_rsa.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
tb_rsa.o: ../../include/openssl/engine.h ../../include/openssl/err.h
tb_rsa.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
tb_rsa.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
tb_rsa.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
tb_rsa.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
tb_rsa.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tb_rsa.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tb_rsa.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
tb_rsa.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
tb_rsa.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
tb_rsa.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tb_rsa.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tb_rsa.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
tb_rsa.o: eng_int.h tb_rsa.c
