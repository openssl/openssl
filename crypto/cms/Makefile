#
# OpenSSL/crypto/cms/Makefile
#

DIR=	cms
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= cms_lib.c cms_asn1.c cms_att.c cms_io.c cms_smime.c cms_err.c \
	cms_sd.c cms_dd.c cms_cd.c cms_env.c cms_enc.c cms_ess.c \
	cms_pwri.c cms_kari.c
LIBOBJ= cms_lib.o cms_asn1.o cms_att.o cms_io.o cms_smime.o cms_err.o \
	cms_sd.o cms_dd.o cms_cd.o cms_env.o cms_enc.o cms_ess.o \
	cms_pwri.o cms_kari.o

SRC= $(LIBSRC)

HEADER=	cms_lcl.h

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
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cms_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_asn1.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_asn1.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_asn1.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_asn1.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_asn1.o: ../../include/openssl/opensslconf.h
cms_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_asn1.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cms_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_asn1.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_asn1.o: ../../include/openssl/x509v3.h cms_asn1.c cms_lcl.h
cms_att.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_att.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_att.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_att.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_att.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_att.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_att.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_att.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_att.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_att.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_att.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cms_att.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_att.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_att.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_att.o: ../../include/openssl/x509v3.h cms_att.c cms_lcl.h
cms_cd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_cd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_cd.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_cd.o: ../../include/openssl/cms.h ../../include/openssl/comp.h
cms_cd.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_cd.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_cd.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_cd.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_cd.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_cd.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_cd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_cd.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_cd.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cms_cd.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_cd.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_cd.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_cd.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
cms_cd.o: cms_cd.c cms_lcl.h
cms_dd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_dd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_dd.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_dd.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_dd.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
cms_dd.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
cms_dd.o: ../../include/openssl/ec.h ../../include/openssl/err.h
cms_dd.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_dd.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_dd.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_dd.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_dd.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_dd.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
cms_dd.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_dd.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_dd.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_dd.o: ../include/internal/cryptlib.h cms_dd.c cms_lcl.h
cms_enc.o: ../../e_os.h ../../include/openssl/asn1.h
cms_enc.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_enc.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_enc.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_enc.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
cms_enc.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
cms_enc.o: ../../include/openssl/ec.h ../../include/openssl/err.h
cms_enc.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_enc.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_enc.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_enc.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
cms_enc.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_enc.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_enc.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
cms_enc.o: cms_enc.c cms_lcl.h
cms_env.o: ../../e_os.h ../../include/openssl/aes.h
cms_env.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_env.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_env.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_env.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_env.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_env.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_env.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_env.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_env.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_env.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_env.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_env.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_env.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
cms_env.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_env.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_env.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_env.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
cms_env.o: cms_env.c cms_lcl.h
cms_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cms_err.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_err.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_err.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
cms_err.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
cms_err.o: ../../include/openssl/ec.h ../../include/openssl/err.h
cms_err.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cms_err.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
cms_err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_err.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_err.o: cms_err.c
cms_ess.o: ../../e_os.h ../../include/openssl/asn1.h
cms_ess.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_ess.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_ess.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_ess.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
cms_ess.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
cms_ess.o: ../../include/openssl/ec.h ../../include/openssl/err.h
cms_ess.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_ess.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_ess.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_ess.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_ess.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_ess.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
cms_ess.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_ess.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_ess.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_ess.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
cms_ess.o: cms_ess.c cms_lcl.h
cms_io.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_io.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_io.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_io.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_io.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_io.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_io.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_io.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_io.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_io.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_io.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_io.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cms_io.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_io.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_io.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_io.o: ../../include/openssl/x509v3.h cms_io.c cms_lcl.h
cms_kari.o: ../../e_os.h ../../include/openssl/aes.h
cms_kari.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_kari.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_kari.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_kari.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_kari.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_kari.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_kari.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_kari.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_kari.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_kari.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_kari.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_kari.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_kari.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
cms_kari.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_kari.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_kari.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_kari.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
cms_kari.o: cms_kari.c cms_lcl.h
cms_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_lib.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_lib.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_lib.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cms_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_lib.o: ../../include/openssl/x509v3.h cms_lcl.h cms_lib.c
cms_pwri.o: ../../e_os.h ../../include/openssl/aes.h
cms_pwri.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_pwri.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cms_pwri.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_pwri.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_pwri.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cms_pwri.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_pwri.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_pwri.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_pwri.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_pwri.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_pwri.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_pwri.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_pwri.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
cms_pwri.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_pwri.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_pwri.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_pwri.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
cms_pwri.o: cms_lcl.h cms_pwri.c
cms_sd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_sd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_sd.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_sd.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_sd.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
cms_sd.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
cms_sd.o: ../../include/openssl/ec.h ../../include/openssl/err.h
cms_sd.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_sd.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_sd.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_sd.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_sd.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_sd.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
cms_sd.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_sd.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_sd.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_sd.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
cms_sd.o: cms_lcl.h cms_sd.c
cms_smime.o: ../../e_os.h ../../include/openssl/asn1.h
cms_smime.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_smime.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cms_smime.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_smime.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
cms_smime.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
cms_smime.o: ../../include/openssl/ec.h ../../include/openssl/err.h
cms_smime.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_smime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_smime.o: ../../include/openssl/opensslconf.h
cms_smime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_smime.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cms_smime.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_smime.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_smime.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_smime.o: ../../include/openssl/x509v3.h ../include/internal/asn1_int.h
cms_smime.o: ../include/internal/cryptlib.h cms_lcl.h cms_smime.c
