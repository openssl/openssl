#
# OpenSSL/crypto/asn1/Makefile
#

DIR=	asn1
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README

LIB=$(TOP)/libcrypto.a
LIBSRC=	a_object.c a_bitstr.c a_utctm.c a_gentm.c a_time.c a_int.c a_octet.c \
	a_print.c a_type.c a_dup.c a_d2i_fp.c a_i2d_fp.c \
	a_utf8.c a_sign.c a_digest.c a_verify.c a_mbstr.c a_strex.c \
	x_algor.c x_val.c x_pubkey.c x_sig.c x_bignum.c \
	x_long.c x_info.c x_spki.c nsseq.c \
	d2i_pu.c d2i_pr.c i2d_pu.c i2d_pr.c\
	t_pkey.c t_spki.c t_bitst.c \
	tasn_new.c tasn_fre.c tasn_enc.c tasn_dec.c tasn_utl.c tasn_typ.c \
	tasn_prn.c tasn_scn.c ameth_lib.c \
	f_int.c f_string.c n_pkey.c \
	x_pkey.c bio_asn1.c bio_ndef.c asn_mime.c \
	asn1_gen.c asn1_par.c asn1_lib.c asn1_err.c a_strnid.c \
	evp_asn1.c asn_pack.c p5_pbe.c p5_pbev2.c p5_scrypt.c p8_pkey.c \
    asn_moid.c asn_mstbl.c
LIBOBJ= a_object.o a_bitstr.o a_utctm.o a_gentm.o a_time.o a_int.o a_octet.o \
	a_print.o a_type.o a_dup.o a_d2i_fp.o a_i2d_fp.o \
	a_utf8.o a_sign.o a_digest.o a_verify.o a_mbstr.o a_strex.o \
	x_algor.o x_val.o x_pubkey.o x_sig.o x_bignum.o \
	x_long.o x_info.o x_spki.o nsseq.o \
	d2i_pu.o d2i_pr.o i2d_pu.o i2d_pr.o \
	t_pkey.o t_spki.o t_bitst.o \
	tasn_new.o tasn_fre.o tasn_enc.o tasn_dec.o tasn_utl.o tasn_typ.o \
	tasn_prn.o tasn_scn.o ameth_lib.o \
	f_int.o f_string.o n_pkey.o \
	x_pkey.o bio_asn1.o bio_ndef.o asn_mime.o \
	asn1_gen.o asn1_par.o asn1_lib.o asn1_err.o a_strnid.o \
	evp_asn1.o asn_pack.o p5_pbe.o p5_pbev2.o p5_scrypt.o p8_pkey.o \
	asn_moid.o asn_mstbl.o

SRC= $(LIBSRC)

HEADER=	asn1_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:	test.c
	cc -g -I../../include -c test.c
	cc -g -I../../include -o test test.o -L../.. -lcrypto

pk:	pk.c
	cc -g -I../../include -c pk.c
	cc -g -I../../include -o pk pk.o -L../.. -lcrypto

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
	@[ -n "$(MAKEDEPEND)" ] # should be set by top Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff


# DO NOT DELETE THIS LINE -- make depend depends on it.

a_bitstr.o: ../../e_os.h ../../include/openssl/asn1.h
a_bitstr.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_bitstr.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_bitstr.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_bitstr.o: ../../include/openssl/opensslconf.h
a_bitstr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_bitstr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_bitstr.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_bitstr.o: a_bitstr.c asn1_locl.h
a_d2i_fp.o: ../../e_os.h ../../include/openssl/asn1.h
a_d2i_fp.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_d2i_fp.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_d2i_fp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_d2i_fp.o: ../../include/openssl/opensslconf.h
a_d2i_fp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_d2i_fp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_d2i_fp.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_d2i_fp.o: a_d2i_fp.c
a_digest.o: ../../e_os.h ../../include/openssl/asn1.h
a_digest.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_digest.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_digest.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
a_digest.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
a_digest.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
a_digest.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_digest.o: ../../include/openssl/opensslconf.h
a_digest.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_digest.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
a_digest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
a_digest.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
a_digest.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
a_digest.o: a_digest.c
a_dup.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_dup.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_dup.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_dup.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_dup.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_dup.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_dup.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_dup.o: a_dup.c
a_gentm.o: ../../e_os.h ../../include/openssl/asn1.h
a_gentm.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_gentm.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_gentm.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_gentm.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_gentm.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_gentm.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_gentm.o: ../include/internal/cryptlib.h a_gentm.c asn1_locl.h
a_i2d_fp.o: ../../e_os.h ../../include/openssl/asn1.h
a_i2d_fp.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_i2d_fp.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_i2d_fp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_i2d_fp.o: ../../include/openssl/opensslconf.h
a_i2d_fp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_i2d_fp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_i2d_fp.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_i2d_fp.o: a_i2d_fp.c
a_int.o: ../../e_os.h ../../include/internal/numbers.h
a_int.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_int.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_int.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_int.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_int.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_int.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_int.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_int.o: ../include/internal/cryptlib.h a_int.c asn1_locl.h
a_mbstr.o: ../../e_os.h ../../include/openssl/asn1.h
a_mbstr.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_mbstr.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_mbstr.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_mbstr.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_mbstr.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_mbstr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_mbstr.o: ../include/internal/cryptlib.h a_mbstr.c
a_object.o: ../../e_os.h ../../include/openssl/asn1.h
a_object.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_object.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_object.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_object.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_object.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_object.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_object.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_object.o: ../../include/openssl/symhacks.h ../include/internal/asn1_int.h
a_object.o: ../include/internal/cryptlib.h a_object.c asn1_locl.h
a_octet.o: ../../e_os.h ../../include/openssl/asn1.h
a_octet.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_octet.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_octet.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_octet.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_octet.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_octet.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_octet.o: ../include/internal/cryptlib.h a_octet.c
a_print.o: ../../e_os.h ../../include/openssl/asn1.h
a_print.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_print.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_print.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_print.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_print.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_print.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_print.o: ../include/internal/cryptlib.h a_print.c
a_sign.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_sign.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_sign.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_sign.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
a_sign.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
a_sign.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
a_sign.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_sign.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_sign.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
a_sign.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
a_sign.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_sign.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_sign.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
a_sign.o: a_sign.c
a_strex.o: ../../e_os.h ../../include/openssl/asn1.h
a_strex.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_strex.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_strex.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
a_strex.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
a_strex.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
a_strex.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_strex.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_strex.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
a_strex.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
a_strex.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_strex.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_strex.o: ../include/internal/cryptlib.h a_strex.c charmap.h
a_strnid.o: ../../e_os.h ../../include/openssl/asn1.h
a_strnid.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_strnid.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_strnid.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_strnid.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_strnid.o: ../../include/openssl/opensslconf.h
a_strnid.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_strnid.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_strnid.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_strnid.o: a_strnid.c
a_time.o: ../../e_os.h ../../include/openssl/asn1.h
a_time.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_time.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_time.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_time.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_time.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_time.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_time.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_time.o: a_time.c asn1_locl.h
a_type.o: ../../e_os.h ../../include/openssl/asn1.h
a_type.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_type.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_type.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_type.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_type.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_type.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_type.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_type.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_type.o: a_type.c asn1_locl.h
a_utctm.o: ../../e_os.h ../../include/openssl/asn1.h
a_utctm.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
a_utctm.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_utctm.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_utctm.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_utctm.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_utctm.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_utctm.o: ../include/internal/cryptlib.h a_utctm.c asn1_locl.h
a_utf8.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_utf8.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_utf8.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_utf8.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_utf8.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_utf8.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_utf8.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_utf8.o: a_utf8.c
a_verify.o: ../../e_os.h ../../include/openssl/asn1.h
a_verify.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_verify.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_verify.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
a_verify.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
a_verify.o: ../../include/openssl/err.h ../../include/openssl/evp.h
a_verify.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_verify.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_verify.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_verify.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
a_verify.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
a_verify.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
a_verify.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
a_verify.o: ../include/internal/cryptlib.h a_verify.c
ameth_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ameth_lib.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
ameth_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ameth_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ameth_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ameth_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
ameth_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ameth_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ameth_lib.o: ../../include/openssl/opensslconf.h
ameth_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ameth_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ameth_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ameth_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ameth_lib.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
ameth_lib.o: ../include/internal/cryptlib.h ameth_lib.c
asn1_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
asn1_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
asn1_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn1_err.o: ../../include/openssl/opensslconf.h
asn1_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_err.o: ../../include/openssl/symhacks.h asn1_err.c
asn1_gen.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_gen.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
asn1_gen.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
asn1_gen.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
asn1_gen.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
asn1_gen.o: ../../include/openssl/err.h ../../include/openssl/evp.h
asn1_gen.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn1_gen.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
asn1_gen.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_gen.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
asn1_gen.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
asn1_gen.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
asn1_gen.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
asn1_gen.o: ../include/internal/cryptlib.h asn1_gen.c
asn1_lib.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
asn1_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
asn1_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn1_lib.o: ../../include/openssl/opensslconf.h
asn1_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_lib.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
asn1_lib.o: asn1_lib.c
asn1_par.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_par.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
asn1_par.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
asn1_par.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn1_par.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn1_par.o: ../../include/openssl/opensslconf.h
asn1_par.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_par.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_par.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
asn1_par.o: asn1_par.c
asn_mime.o: ../../e_os.h ../../include/openssl/asn1.h
asn_mime.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
asn_mime.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
asn_mime.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
asn_mime.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
asn_mime.o: ../../include/openssl/err.h ../../include/openssl/evp.h
asn_mime.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn_mime.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
asn_mime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_mime.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
asn_mime.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
asn_mime.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
asn_mime.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
asn_mime.o: ../include/internal/cryptlib.h asn1_locl.h asn_mime.c
asn_moid.o: ../../e_os.h ../../include/openssl/asn1.h
asn_moid.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
asn_moid.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
asn_moid.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
asn_moid.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
asn_moid.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
asn_moid.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
asn_moid.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn_moid.o: ../../include/openssl/opensslconf.h
asn_moid.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_moid.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
asn_moid.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
asn_moid.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
asn_moid.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
asn_moid.o: ../include/internal/cryptlib.h asn_moid.c
asn_mstbl.o: ../../e_os.h ../../include/openssl/asn1.h
asn_mstbl.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
asn_mstbl.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
asn_mstbl.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
asn_mstbl.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
asn_mstbl.o: ../../include/openssl/err.h ../../include/openssl/evp.h
asn_mstbl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn_mstbl.o: ../../include/openssl/objects.h
asn_mstbl.o: ../../include/openssl/opensslconf.h
asn_mstbl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_mstbl.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
asn_mstbl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
asn_mstbl.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
asn_mstbl.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
asn_mstbl.o: ../include/internal/cryptlib.h asn_mstbl.c
asn_pack.o: ../../e_os.h ../../include/openssl/asn1.h
asn_pack.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
asn_pack.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
asn_pack.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn_pack.o: ../../include/openssl/opensslconf.h
asn_pack.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_pack.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn_pack.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
asn_pack.o: asn_pack.c
bio_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bio_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
bio_asn1.o: ../../include/openssl/opensslconf.h
bio_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
bio_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bio_asn1.o: ../../include/openssl/symhacks.h bio_asn1.c
bio_ndef.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
bio_ndef.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
bio_ndef.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bio_ndef.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bio_ndef.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
bio_ndef.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bio_ndef.o: ../../include/openssl/symhacks.h bio_ndef.c
d2i_pr.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
d2i_pr.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
d2i_pr.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
d2i_pr.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
d2i_pr.o: ../../include/openssl/ecdsa.h ../../include/openssl/engine.h
d2i_pr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
d2i_pr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
d2i_pr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
d2i_pr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
d2i_pr.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
d2i_pr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
d2i_pr.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
d2i_pr.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
d2i_pr.o: ../include/internal/cryptlib.h d2i_pr.c
d2i_pu.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
d2i_pu.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
d2i_pu.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
d2i_pu.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
d2i_pu.o: ../../include/openssl/err.h ../../include/openssl/evp.h
d2i_pu.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
d2i_pu.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
d2i_pu.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
d2i_pu.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
d2i_pu.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
d2i_pu.o: ../include/internal/cryptlib.h d2i_pu.c
evp_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
evp_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
evp_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
evp_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
evp_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
evp_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
evp_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_asn1.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
evp_asn1.o: evp_asn1.c
f_int.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
f_int.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
f_int.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
f_int.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
f_int.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
f_int.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
f_int.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
f_int.o: f_int.c
f_string.o: ../../e_os.h ../../include/openssl/asn1.h
f_string.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
f_string.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
f_string.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
f_string.o: ../../include/openssl/opensslconf.h
f_string.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
f_string.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
f_string.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
f_string.o: f_string.c
i2d_pr.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
i2d_pr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
i2d_pr.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
i2d_pr.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
i2d_pr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
i2d_pr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
i2d_pr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
i2d_pr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
i2d_pr.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
i2d_pr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
i2d_pr.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
i2d_pr.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
i2d_pr.o: ../include/internal/cryptlib.h i2d_pr.c
i2d_pu.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
i2d_pu.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
i2d_pu.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
i2d_pu.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
i2d_pu.o: ../../include/openssl/err.h ../../include/openssl/evp.h
i2d_pu.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
i2d_pu.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
i2d_pu.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
i2d_pu.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
i2d_pu.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
i2d_pu.o: ../include/internal/cryptlib.h i2d_pu.c
n_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
n_pkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
n_pkey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
n_pkey.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
n_pkey.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
n_pkey.o: ../../include/openssl/err.h ../../include/openssl/evp.h
n_pkey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
n_pkey.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
n_pkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
n_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
n_pkey.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
n_pkey.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
n_pkey.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
n_pkey.o: ../include/internal/cryptlib.h n_pkey.c
nsseq.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
nsseq.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
nsseq.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
nsseq.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
nsseq.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
nsseq.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
nsseq.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
nsseq.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
nsseq.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
nsseq.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
nsseq.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
nsseq.o: ../../include/openssl/x509_vfy.h nsseq.c
p5_pbe.o: ../../e_os.h ../../include/openssl/asn1.h
p5_pbe.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_pbe.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p5_pbe.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p5_pbe.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p5_pbe.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p5_pbe.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p5_pbe.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p5_pbe.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p5_pbe.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_pbe.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p5_pbe.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p5_pbe.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_pbe.o: ../include/internal/cryptlib.h p5_pbe.c
p5_pbev2.o: ../../e_os.h ../../include/openssl/asn1.h
p5_pbev2.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_pbev2.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p5_pbev2.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p5_pbev2.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p5_pbev2.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p5_pbev2.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p5_pbev2.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p5_pbev2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p5_pbev2.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_pbev2.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p5_pbev2.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p5_pbev2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_pbev2.o: ../include/internal/cryptlib.h p5_pbev2.c
p5_scrypt.o: ../../e_os.h ../../include/openssl/asn1.h
p5_scrypt.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_scrypt.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p5_scrypt.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p5_scrypt.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p5_scrypt.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p5_scrypt.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p5_scrypt.o: ../../include/openssl/objects.h
p5_scrypt.o: ../../include/openssl/opensslconf.h
p5_scrypt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p5_scrypt.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_scrypt.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p5_scrypt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p5_scrypt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_scrypt.o: ../include/internal/cryptlib.h p5_scrypt.c
p8_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
p8_pkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p8_pkey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p8_pkey.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p8_pkey.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p8_pkey.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p8_pkey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p8_pkey.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p8_pkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p8_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p8_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p8_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p8_pkey.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
p8_pkey.o: p8_pkey.c
t_bitst.o: ../../e_os.h ../../include/openssl/asn1.h
t_bitst.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
t_bitst.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
t_bitst.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
t_bitst.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
t_bitst.o: ../../include/openssl/err.h ../../include/openssl/evp.h
t_bitst.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_bitst.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
t_bitst.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
t_bitst.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
t_bitst.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
t_bitst.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
t_bitst.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
t_bitst.o: ../include/internal/cryptlib.h t_bitst.c
t_pkey.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_pkey.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
t_pkey.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
t_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
t_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_pkey.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
t_pkey.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
t_pkey.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
t_pkey.o: ../include/internal/bn_int.h ../include/internal/cryptlib.h t_pkey.c
t_spki.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_spki.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
t_spki.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
t_spki.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
t_spki.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
t_spki.o: ../../include/openssl/err.h ../../include/openssl/evp.h
t_spki.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_spki.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
t_spki.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
t_spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
t_spki.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
t_spki.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
t_spki.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
t_spki.o: ../include/internal/cryptlib.h t_spki.c
tasn_dec.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_dec.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
tasn_dec.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_dec.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tasn_dec.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_dec.o: ../../include/openssl/opensslconf.h
tasn_dec.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_dec.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_dec.o: ../../include/openssl/symhacks.h asn1_locl.h tasn_dec.c
tasn_enc.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_enc.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_enc.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tasn_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
tasn_enc.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_enc.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_enc.o: ../../include/openssl/symhacks.h ../include/internal/asn1_int.h
tasn_enc.o: ../include/internal/cryptlib.h asn1_locl.h tasn_enc.c
tasn_fre.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_fre.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
tasn_fre.o: ../../include/openssl/e_os2.h ../../include/openssl/obj_mac.h
tasn_fre.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_fre.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_fre.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_fre.o: ../../include/openssl/symhacks.h asn1_locl.h tasn_fre.c
tasn_new.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_new.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
tasn_new.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
tasn_new.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_new.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_new.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_new.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_new.o: ../../include/openssl/symhacks.h asn1_locl.h tasn_new.c
tasn_prn.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_prn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_prn.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
tasn_prn.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_prn.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
tasn_prn.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
tasn_prn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tasn_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_prn.o: ../../include/openssl/opensslconf.h
tasn_prn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_prn.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tasn_prn.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tasn_prn.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
tasn_prn.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
tasn_prn.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
tasn_prn.o: asn1_locl.h tasn_prn.c
tasn_scn.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_scn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_scn.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
tasn_scn.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_scn.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
tasn_scn.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
tasn_scn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
tasn_scn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_scn.o: ../../include/openssl/opensslconf.h
tasn_scn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_scn.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
tasn_scn.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
tasn_scn.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
tasn_scn.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
tasn_scn.o: ../include/internal/cryptlib.h asn1_locl.h tasn_scn.c
tasn_typ.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_typ.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
tasn_typ.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
tasn_typ.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_typ.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_typ.o: ../../include/openssl/symhacks.h tasn_typ.c
tasn_utl.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_utl.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_utl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tasn_utl.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
tasn_utl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_utl.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_utl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_utl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_utl.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
tasn_utl.o: asn1_locl.h tasn_utl.c
x_algor.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
x_algor.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x_algor.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x_algor.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_algor.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
x_algor.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_algor.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_algor.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_algor.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_algor.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_algor.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_algor.o: ../../include/openssl/x509_vfy.h x_algor.c
x_bignum.o: ../../e_os.h ../../include/openssl/asn1.h
x_bignum.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_bignum.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_bignum.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x_bignum.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_bignum.o: ../../include/openssl/opensslconf.h
x_bignum.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_bignum.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
x_bignum.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
x_bignum.o: x_bignum.c
x_info.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_info.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_info.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_info.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_info.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_info.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_info.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_info.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_info.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_info.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_info.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_info.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_info.o: x_info.c
x_long.o: ../../e_os.h ../../include/openssl/asn1.h
x_long.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_long.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_long.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x_long.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_long.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_long.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
x_long.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x_long.o: ../include/internal/cryptlib.h x_long.c
x_pkey.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_pkey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_pkey.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_pkey.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_pkey.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_pkey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_pkey.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_pkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_pkey.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_pkey.o: x_pkey.c
x_pubkey.o: ../../e_os.h ../../include/openssl/asn1.h
x_pubkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_pubkey.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_pubkey.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_pubkey.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_pubkey.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x_pubkey.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_pubkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_pubkey.o: ../../include/openssl/opensslconf.h
x_pubkey.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_pubkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
x_pubkey.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x_pubkey.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x_pubkey.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x_pubkey.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
x_pubkey.o: x_pubkey.c
x_sig.o: ../../e_os.h ../../include/openssl/asn1.h
x_sig.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_sig.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_sig.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_sig.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_sig.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_sig.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_sig.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_sig.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_sig.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_sig.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_sig.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_sig.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_sig.o: x_sig.c
x_spki.o: ../../e_os.h ../../include/openssl/asn1.h
x_spki.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_spki.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_spki.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_spki.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_spki.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_spki.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_spki.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_spki.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_spki.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_spki.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_spki.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_spki.o: x_spki.c
x_val.o: ../../e_os.h ../../include/openssl/asn1.h
x_val.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_val.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_val.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_val.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_val.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_val.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_val.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_val.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_val.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_val.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_val.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_val.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_val.o: x_val.c
