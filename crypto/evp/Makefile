#
# OpenSSL/crypto/evp/Makefile
#

DIR=	evp
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=evp_test.c
TESTDATA=evptests.txt
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= encode.c digest.c evp_enc.c evp_key.c evp_acnf.c evp_cnf.c \
	e_des.c e_bf.c e_idea.c e_des3.c e_camellia.c\
	e_rc4.c e_aes.c names.c e_seed.c \
	e_xcbc_d.c e_rc2.c e_cast.c e_rc5.c \
	m_null.c m_md2.c m_md4.c m_md5.c m_sha.c m_sha1.c m_wp.c \
	m_dss.c m_dss1.c m_mdc2.c m_ripemd.c m_ecdsa.c\
	p_open.c p_seal.c p_sign.c p_verify.c p_lib.c p_enc.c p_dec.c \
	bio_md.c bio_b64.c bio_enc.c evp_err.c e_null.c \
	c_all.c c_allc.c c_alld.c evp_lib.c bio_ok.c \
	evp_pkey.c evp_pbe.c p5_crpt.c p5_crpt2.c \
	e_old.c pmeth_lib.c pmeth_fn.c pmeth_gn.c m_sigver.c evp_fips.c	\
	e_aes_cbc_hmac_sha1.c e_rc4_hmac_md5.c

LIBOBJ=	encode.o digest.o evp_enc.o evp_key.o evp_acnf.o evp_cnf.o \
	e_des.o e_bf.o e_idea.o e_des3.o e_camellia.o\
	e_rc4.o e_aes.o names.o e_seed.o \
	e_xcbc_d.o e_rc2.o e_cast.o e_rc5.o \
	m_null.o m_md2.o m_md4.o m_md5.o m_sha.o m_sha1.o m_wp.o \
	m_dss.o m_dss1.o m_mdc2.o m_ripemd.o m_ecdsa.o\
	p_open.o p_seal.o p_sign.o p_verify.o p_lib.o p_enc.o p_dec.o \
	bio_md.o bio_b64.o bio_enc.o evp_err.o e_null.o \
	c_all.o c_allc.o c_alld.o evp_lib.o bio_ok.o \
	evp_pkey.o evp_pbe.o p5_crpt.o p5_crpt2.o \
	e_old.o pmeth_lib.o pmeth_fn.o pmeth_gn.o m_sigver.o evp_fips.o \
	e_aes_cbc_hmac_sha1.o e_rc4_hmac_md5.o

SRC= $(LIBSRC)

EXHEADER= evp.h
HEADER=	evp_locl.h $(EXHEADER)

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
	@[ -f $(TESTDATA) ] && cp $(TESTDATA) ../../test && echo "$(TESTDATA) -> ../../test/$(TESTDATA)"
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

bio_b64.o: ../../e_os.h ../../include/openssl/asn1.h
bio_b64.o: ../../include/openssl/bio.h ../../include/openssl/err.h
bio_b64.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
bio_b64.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
bio_b64.o: ../../include/openssl/stack.h ../cryptlib.h bio_b64.c
bio_enc.o: ../../e_os.h ../../include/openssl/asn1.h
bio_enc.o: ../../include/openssl/bio.h ../../include/openssl/err.h
bio_enc.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
bio_enc.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
bio_enc.o: ../../include/openssl/stack.h ../cryptlib.h bio_enc.c
bio_md.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
bio_md.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bio_md.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
bio_md.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bio_md.o: ../cryptlib.h bio_md.c
bio_ok.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
bio_ok.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bio_ok.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
bio_ok.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
bio_ok.o: ../../include/openssl/stack.h ../cryptlib.h bio_ok.c
c_all.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
c_all.o: ../../include/openssl/engine.h ../../include/openssl/err.h
c_all.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
c_all.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
c_all.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
c_all.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
c_all.o: ../cryptlib.h c_all.c
c_allc.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
c_allc.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
c_allc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
c_allc.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
c_allc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
c_allc.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
c_allc.o: ../cryptlib.h c_allc.c
c_alld.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
c_alld.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
c_alld.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
c_alld.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
c_alld.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
c_alld.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
c_alld.o: ../cryptlib.h c_alld.c
digest.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
digest.o: ../../include/openssl/engine.h ../../include/openssl/err.h
digest.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
digest.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
digest.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
digest.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
digest.o: ../cryptlib.h digest.c
e_aes.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_aes.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_aes.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_aes.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
e_aes.o: e_aes.c evp_locl.h
e_aes_cbc_hmac_sha1.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_aes_cbc_hmac_sha1.o: ../../include/openssl/obj_mac.h
e_aes_cbc_hmac_sha1.o: ../../include/openssl/objects.h
e_aes_cbc_hmac_sha1.o: ../../include/openssl/safestack.h
e_aes_cbc_hmac_sha1.o: ../../include/openssl/stack.h e_aes_cbc_hmac_sha1.c
e_aes_cbc_hmac_sha1.o: evp_locl.h
e_bf.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_bf.o: ../../include/openssl/blowfish.h ../../include/openssl/err.h
e_bf.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
e_bf.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
e_bf.o: ../../include/openssl/stack.h ../cryptlib.h e_bf.c evp_locl.h
e_camellia.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_camellia.o: ../../include/openssl/camellia.h ../../include/openssl/err.h
e_camellia.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
e_camellia.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
e_camellia.o: ../../include/openssl/stack.h e_camellia.c evp_locl.h
e_cast.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_cast.o: ../../include/openssl/cast.h ../../include/openssl/err.h
e_cast.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
e_cast.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
e_cast.o: ../../include/openssl/stack.h ../cryptlib.h e_cast.c evp_locl.h
e_des.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_des.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_des.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_des.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
e_des.o: ../../include/openssl/stack.h ../../include/openssl/ui.h
e_des.o: ../../include/openssl/ui_compat.h ../cryptlib.h e_des.c evp_locl.h
e_des3.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_des3.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_des3.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_des3.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
e_des3.o: ../../include/openssl/stack.h ../../include/openssl/ui.h
e_des3.o: ../../include/openssl/ui_compat.h ../cryptlib.h e_des3.c evp_locl.h
e_idea.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_idea.o: ../../include/openssl/err.h ../../include/openssl/idea.h
e_idea.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
e_idea.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
e_idea.o: ../../include/openssl/stack.h ../cryptlib.h e_idea.c evp_locl.h
e_null.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_null.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_null.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_null.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
e_null.o: ../cryptlib.h e_null.c
e_old.o: e_old.c
e_rc2.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_rc2.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_rc2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_rc2.o: ../../include/openssl/rc2.h ../../include/openssl/safestack.h
e_rc2.o: ../../include/openssl/stack.h ../cryptlib.h e_rc2.c evp_locl.h
e_rc4.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_rc4.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_rc4.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_rc4.o: ../../include/openssl/rc4.h ../../include/openssl/safestack.h
e_rc4.o: ../../include/openssl/stack.h ../cryptlib.h e_rc4.c evp_locl.h
e_rc4_hmac_md5.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_rc4_hmac_md5.o: ../../include/openssl/md5.h ../../include/openssl/obj_mac.h
e_rc4_hmac_md5.o: ../../include/openssl/objects.h ../../include/openssl/rc4.h
e_rc4_hmac_md5.o: ../../include/openssl/safestack.h
e_rc4_hmac_md5.o: ../../include/openssl/stack.h e_rc4_hmac_md5.c
e_rc5.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
e_rc5.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
e_rc5.o: ../../include/openssl/stack.h ../cryptlib.h e_rc5.c
e_seed.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_seed.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
e_seed.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
e_seed.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
e_seed.o: ../../include/openssl/stack.h e_seed.c evp_locl.h
e_xcbc_d.o: ../../e_os.h ../../include/openssl/asn1.h
e_xcbc_d.o: ../../include/openssl/bio.h ../../include/openssl/err.h
e_xcbc_d.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
e_xcbc_d.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
e_xcbc_d.o: ../../include/openssl/stack.h ../../include/openssl/ui.h
e_xcbc_d.o: ../../include/openssl/ui_compat.h ../cryptlib.h e_xcbc_d.c
e_xcbc_d.o: evp_locl.h
encode.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
encode.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
encode.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
encode.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
encode.o: ../cryptlib.h encode.c
evp_acnf.o: ../../e_os.h ../../include/openssl/asn1.h
evp_acnf.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
evp_acnf.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
evp_acnf.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
evp_acnf.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_acnf.o: ../cryptlib.h evp_acnf.c
evp_cnf.o: ../../e_os.h ../../include/openssl/asn1.h
evp_cnf.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
evp_cnf.o: ../../include/openssl/dso.h ../../include/openssl/err.h
evp_cnf.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
evp_cnf.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
evp_cnf.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_cnf.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
evp_cnf.o: ../../include/openssl/x509v3.h ../cryptlib.h evp_cnf.c
evp_enc.o: ../../e_os.h ../../include/openssl/asn1.h
evp_enc.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
evp_enc.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
evp_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
evp_enc.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
evp_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_enc.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
evp_enc.o: ../cryptlib.h evp_enc.c evp_locl.h
evp_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
evp_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
evp_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
evp_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_err.o: evp_err.c
evp_fips.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
evp_fips.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
evp_fips.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_fips.o: evp_fips.c
evp_key.o: ../../e_os.h ../../include/openssl/asn1.h
evp_key.o: ../../include/openssl/bio.h ../../include/openssl/err.h
evp_key.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
evp_key.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
evp_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_key.o: ../../include/openssl/ui.h ../../include/openssl/x509.h
evp_key.o: ../../include/openssl/x509_vfy.h ../cryptlib.h evp_key.c
evp_lib.o: ../../e_os.h ../../include/openssl/asn1.h
evp_lib.o: ../../include/openssl/bio.h ../../include/openssl/err.h
evp_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
evp_lib.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
evp_lib.o: ../../include/openssl/stack.h ../cryptlib.h evp_lib.c
evp_pbe.o: ../../e_os.h ../../include/openssl/asn1.h
evp_pbe.o: ../../include/openssl/bio.h ../../include/openssl/err.h
evp_pbe.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
evp_pbe.o: ../../include/openssl/objects.h ../../include/openssl/pkcs12.h
evp_pbe.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
evp_pbe.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
evp_pbe.o: ../../include/openssl/x509_vfy.h ../cryptlib.h evp_locl.h evp_pbe.c
evp_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
evp_pkey.o: ../../include/openssl/bio.h ../../include/openssl/err.h
evp_pkey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
evp_pkey.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
evp_pkey.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
evp_pkey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
evp_pkey.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
evp_pkey.o: evp_pkey.c
m_dss.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_dss.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_dss.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
m_dss.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_dss.o: ../cryptlib.h m_dss.c
m_dss1.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_dss1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_dss1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
m_dss1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_dss1.o: ../cryptlib.h m_dss1.c
m_ecdsa.o: ../../e_os.h ../../include/openssl/asn1.h
m_ecdsa.o: ../../include/openssl/bio.h ../../include/openssl/err.h
m_ecdsa.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
m_ecdsa.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
m_ecdsa.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_ecdsa.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_ecdsa.o: ../cryptlib.h m_ecdsa.c
m_md2.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
m_md2.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
m_md2.o: ../../include/openssl/stack.h ../cryptlib.h m_md2.c
m_md4.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_md4.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_md4.o: ../../include/openssl/md4.h ../../include/openssl/obj_mac.h
m_md4.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
m_md4.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_md4.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_md4.o: ../cryptlib.h evp_locl.h m_md4.c
m_md5.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_md5.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_md5.o: ../../include/openssl/md5.h ../../include/openssl/obj_mac.h
m_md5.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
m_md5.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_md5.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_md5.o: ../cryptlib.h evp_locl.h m_md5.c
m_mdc2.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_mdc2.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_mdc2.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
m_mdc2.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
m_mdc2.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_mdc2.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
m_mdc2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_mdc2.o: ../cryptlib.h evp_locl.h m_mdc2.c
m_null.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_null.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_null.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
m_null.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
m_null.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
m_null.o: ../../include/openssl/x509_vfy.h ../cryptlib.h m_null.c
m_ripemd.o: ../../e_os.h ../../include/openssl/asn1.h
m_ripemd.o: ../../include/openssl/bio.h ../../include/openssl/err.h
m_ripemd.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
m_ripemd.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
m_ripemd.o: ../../include/openssl/ripemd.h ../../include/openssl/safestack.h
m_ripemd.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
m_ripemd.o: ../../include/openssl/x509_vfy.h ../cryptlib.h evp_locl.h
m_ripemd.o: m_ripemd.c
m_sha.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_sha.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_sha.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
m_sha.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
m_sha.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
m_sha.o: ../../include/openssl/x509_vfy.h ../cryptlib.h evp_locl.h m_sha.c
m_sha1.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
m_sha1.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
m_sha1.o: ../../include/openssl/stack.h ../cryptlib.h m_sha1.c
m_sigver.o: ../../e_os.h ../../include/openssl/asn1.h
m_sigver.o: ../../include/openssl/bio.h ../../include/openssl/err.h
m_sigver.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
m_sigver.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
m_sigver.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
m_sigver.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_sigver.o: ../cryptlib.h evp_locl.h m_sigver.c
m_wp.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_wp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
m_wp.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
m_wp.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
m_wp.o: ../../include/openssl/stack.h ../../include/openssl/whrlpool.h
m_wp.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_wp.o: ../cryptlib.h evp_locl.h m_wp.c
names.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
names.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
names.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
names.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
names.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
names.o: ../../include/openssl/x509_vfy.h ../cryptlib.h names.c
p5_crpt.o: ../../e_os.h ../../include/openssl/asn1.h
p5_crpt.o: ../../include/openssl/bio.h ../../include/openssl/err.h
p5_crpt.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p5_crpt.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
p5_crpt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p5_crpt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_crpt.o: ../cryptlib.h p5_crpt.c
p5_crpt2.o: ../../e_os.h ../../include/openssl/asn1.h
p5_crpt2.o: ../../include/openssl/bio.h ../../include/openssl/err.h
p5_crpt2.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p5_crpt2.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
p5_crpt2.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p5_crpt2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_crpt2.o: ../cryptlib.h evp_locl.h p5_crpt2.c
p_dec.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
p_dec.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p_dec.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p_dec.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p_dec.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p_dec.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p_dec.o: ../cryptlib.h p_dec.c
p_enc.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
p_enc.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p_enc.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p_enc.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p_enc.o: ../cryptlib.h p_enc.c
p_lib.o: ../../e_os.h ../../include/openssl/asn1.h
p_lib.o: ../../include/openssl/asn1_mac.h ../../include/openssl/bio.h
p_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
p_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p_lib.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
p_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p_lib.o: ../asn1/asn1_locl.h ../cryptlib.h p_lib.c
p_open.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
p_open.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p_open.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p_open.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p_open.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
p_open.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p_open.c
p_seal.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
p_seal.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p_seal.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p_seal.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p_seal.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p_seal.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p_seal.o: ../cryptlib.h p_seal.c
p_sign.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
p_sign.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p_sign.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p_sign.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p_sign.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
p_sign.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p_sign.c
p_verify.o: ../../e_os.h ../../include/openssl/asn1.h
p_verify.o: ../../include/openssl/bio.h ../../include/openssl/err.h
p_verify.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p_verify.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
p_verify.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p_verify.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p_verify.o: ../cryptlib.h p_verify.c
pmeth_fn.o: ../../e_os.h ../../include/openssl/asn1.h
pmeth_fn.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pmeth_fn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pmeth_fn.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
pmeth_fn.o: ../../include/openssl/stack.h ../cryptlib.h evp_locl.h pmeth_fn.c
pmeth_gn.o: ../../e_os.h ../../include/openssl/asn1.h
pmeth_gn.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pmeth_gn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pmeth_gn.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
pmeth_gn.o: ../../include/openssl/stack.h ../cryptlib.h evp_locl.h pmeth_gn.c
pmeth_lib.o: ../../e_os.h ../../include/openssl/asn1.h
pmeth_lib.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
pmeth_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pmeth_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pmeth_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pmeth_lib.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pmeth_lib.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
pmeth_lib.o: evp_locl.h pmeth_lib.c
