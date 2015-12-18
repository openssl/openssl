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
a_bitstr.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_bitstr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_bitstr.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_bitstr.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_bitstr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_bitstr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_bitstr.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_bitstr.o: a_bitstr.c asn1_locl.h
a_d2i_fp.o: ../../e_os.h ../../include/openssl/asn1.h
a_d2i_fp.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_d2i_fp.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_d2i_fp.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_d2i_fp.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_d2i_fp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_d2i_fp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_d2i_fp.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_d2i_fp.o: a_d2i_fp.c
a_digest.o: ../../e_os.h ../../include/openssl/asn1.h
a_digest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_digest.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_digest.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
a_digest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
a_digest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
a_digest.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_digest.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_digest.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_digest.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
a_digest.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
a_digest.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_digest.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_digest.o: ../include/internal/cryptlib.h a_digest.c
a_dup.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_dup.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_dup.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_dup.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_dup.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_dup.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_dup.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_dup.o: ../include/internal/cryptlib.h a_dup.c
a_gentm.o: ../../e_os.h ../../include/openssl/asn1.h
a_gentm.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_gentm.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_gentm.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_gentm.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_gentm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_gentm.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_gentm.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_gentm.o: a_gentm.c asn1_locl.h
a_i2d_fp.o: ../../e_os.h ../../include/openssl/asn1.h
a_i2d_fp.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_i2d_fp.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_i2d_fp.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_i2d_fp.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
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
a_mbstr.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_mbstr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_mbstr.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_mbstr.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_mbstr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_mbstr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_mbstr.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_mbstr.o: a_mbstr.c
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
a_octet.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_octet.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_octet.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_octet.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_octet.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_octet.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_octet.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_octet.o: a_octet.c
a_print.o: ../../e_os.h ../../include/openssl/asn1.h
a_print.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_print.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_print.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_print.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_print.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_print.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_print.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_print.o: a_print.c
a_sign.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_sign.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_sign.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
a_sign.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
a_sign.o: ../../include/openssl/ec.h ../../include/openssl/err.h
a_sign.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
a_sign.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_sign.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_sign.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
a_sign.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
a_sign.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
a_sign.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
a_sign.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
a_sign.o: ../include/internal/cryptlib.h ../include/internal/evp_int.h a_sign.c
a_strex.o: ../../e_os.h ../../include/openssl/asn1.h
a_strex.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_strex.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_strex.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
a_strex.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
a_strex.o: ../../include/openssl/err.h ../../include/openssl/evp.h
a_strex.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_strex.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_strex.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_strex.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
a_strex.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
a_strex.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_strex.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_strex.o: ../include/internal/cryptlib.h a_strex.c charmap.h
a_strnid.o: ../../e_os.h ../../include/openssl/asn1.h
a_strnid.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_strnid.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_strnid.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_strnid.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_strnid.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_strnid.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_strnid.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_strnid.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_strnid.o: a_strnid.c
a_time.o: ../../e_os.h ../../include/openssl/asn1.h
a_time.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_time.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_time.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_time.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_time.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_time.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_time.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_time.o: ../include/internal/cryptlib.h a_time.c asn1_locl.h
a_type.o: ../../e_os.h ../../include/openssl/asn1.h
a_type.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_type.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_type.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_type.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_type.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_type.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_type.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_type.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_type.o: ../include/internal/cryptlib.h a_type.c asn1_locl.h
a_utctm.o: ../../e_os.h ../../include/openssl/asn1.h
a_utctm.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_utctm.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_utctm.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
a_utctm.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
a_utctm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_utctm.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_utctm.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
a_utctm.o: a_utctm.c asn1_locl.h
a_utf8.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_utf8.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
a_utf8.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
a_utf8.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_utf8.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
a_utf8.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
a_utf8.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_utf8.o: ../include/internal/cryptlib.h a_utf8.c
a_verify.o: ../../e_os.h ../../include/openssl/asn1.h
a_verify.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
a_verify.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
a_verify.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
a_verify.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
a_verify.o: ../../include/openssl/err.h ../../include/openssl/evp.h
a_verify.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_verify.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
a_verify.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
a_verify.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
a_verify.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
a_verify.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
a_verify.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_verify.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
a_verify.o: a_verify.c
ameth_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ameth_lib.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
ameth_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ameth_lib.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
ameth_lib.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
ameth_lib.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
ameth_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ameth_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ameth_lib.o: ../../include/openssl/objects.h
ameth_lib.o: ../../include/openssl/opensslconf.h
ameth_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ameth_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
ameth_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ameth_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ameth_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
ameth_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ameth_lib.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
ameth_lib.o: ameth_lib.c
asn1_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
asn1_err.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
asn1_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
asn1_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
asn1_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_err.o: ../../include/openssl/symhacks.h asn1_err.c
asn1_gen.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_gen.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
asn1_gen.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
asn1_gen.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
asn1_gen.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
asn1_gen.o: ../../include/openssl/ec.h ../../include/openssl/err.h
asn1_gen.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
asn1_gen.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn1_gen.o: ../../include/openssl/opensslconf.h
asn1_gen.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_gen.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
asn1_gen.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
asn1_gen.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
asn1_gen.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
asn1_gen.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
asn1_gen.o: asn1_gen.c
asn1_lib.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
asn1_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
asn1_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
asn1_lib.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
asn1_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_lib.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
asn1_lib.o: asn1_lib.c
asn1_par.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_par.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
asn1_par.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
asn1_par.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
asn1_par.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn1_par.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
asn1_par.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn1_par.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_par.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
asn1_par.o: asn1_par.c
asn_mime.o: ../../e_os.h ../../include/openssl/asn1.h
asn_mime.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
asn_mime.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
asn_mime.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
asn_mime.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
asn_mime.o: ../../include/openssl/ec.h ../../include/openssl/err.h
asn_mime.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
asn_mime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn_mime.o: ../../include/openssl/opensslconf.h
asn_mime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_mime.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
asn_mime.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
asn_mime.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
asn_mime.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
asn_mime.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
asn_mime.o: ../include/internal/evp_int.h asn1_locl.h asn_mime.c
asn_moid.o: ../../e_os.h ../../include/openssl/asn1.h
asn_moid.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
asn_moid.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
asn_moid.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
asn_moid.o: ../../include/openssl/dsa.h ../../include/openssl/dso.h
asn_moid.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
asn_moid.o: ../../include/openssl/err.h ../../include/openssl/evp.h
asn_moid.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn_moid.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
asn_moid.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_moid.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
asn_moid.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
asn_moid.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
asn_moid.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
asn_moid.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
asn_moid.o: asn_moid.c
asn_mstbl.o: ../../e_os.h ../../include/openssl/asn1.h
asn_mstbl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
asn_mstbl.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
asn_mstbl.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
asn_mstbl.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
asn_mstbl.o: ../../include/openssl/ec.h ../../include/openssl/err.h
asn_mstbl.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
asn_mstbl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn_mstbl.o: ../../include/openssl/opensslconf.h
asn_mstbl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_mstbl.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
asn_mstbl.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
asn_mstbl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
asn_mstbl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
asn_mstbl.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
asn_mstbl.o: asn_mstbl.c
asn_pack.o: ../../e_os.h ../../include/openssl/asn1.h
asn_pack.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
asn_pack.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
asn_pack.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
asn_pack.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
asn_pack.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
asn_pack.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn_pack.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
asn_pack.o: asn_pack.c
bio_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bio_asn1.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
bio_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
bio_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
bio_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bio_asn1.o: ../../include/openssl/symhacks.h bio_asn1.c
bio_ndef.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
bio_ndef.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bio_ndef.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
bio_ndef.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bio_ndef.o: ../../include/openssl/opensslconf.h
bio_ndef.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
bio_ndef.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bio_ndef.o: ../../include/openssl/symhacks.h bio_ndef.c
d2i_pr.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
d2i_pr.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
d2i_pr.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
d2i_pr.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
d2i_pr.o: ../../include/openssl/ec.h ../../include/openssl/engine.h
d2i_pr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
d2i_pr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
d2i_pr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
d2i_pr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
d2i_pr.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
d2i_pr.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
d2i_pr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
d2i_pr.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
d2i_pr.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
d2i_pr.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
d2i_pr.o: d2i_pr.c
d2i_pu.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
d2i_pu.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
d2i_pu.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
d2i_pu.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
d2i_pu.o: ../../include/openssl/ec.h ../../include/openssl/err.h
d2i_pu.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
d2i_pu.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
d2i_pu.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
d2i_pu.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rsa.h
d2i_pu.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
d2i_pu.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
d2i_pu.o: d2i_pu.c
evp_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
evp_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
evp_asn1.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
evp_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
evp_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
evp_asn1.o: ../../include/openssl/opensslconf.h
evp_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
evp_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_asn1.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
evp_asn1.o: evp_asn1.c
f_int.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
f_int.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
f_int.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
f_int.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
f_int.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
f_int.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
f_int.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
f_int.o: ../include/internal/cryptlib.h f_int.c
f_string.o: ../../e_os.h ../../include/openssl/asn1.h
f_string.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
f_string.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
f_string.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
f_string.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
f_string.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
f_string.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
f_string.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
f_string.o: f_string.c
i2d_pr.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
i2d_pr.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
i2d_pr.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
i2d_pr.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
i2d_pr.o: ../../include/openssl/ec.h ../../include/openssl/err.h
i2d_pr.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
i2d_pr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
i2d_pr.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
i2d_pr.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
i2d_pr.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
i2d_pr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
i2d_pr.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
i2d_pr.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
i2d_pr.o: ../include/internal/cryptlib.h i2d_pr.c
i2d_pu.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
i2d_pu.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
i2d_pu.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
i2d_pu.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
i2d_pu.o: ../../include/openssl/ec.h ../../include/openssl/err.h
i2d_pu.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
i2d_pu.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
i2d_pu.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
i2d_pu.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rsa.h
i2d_pu.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
i2d_pu.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
i2d_pu.o: i2d_pu.c
n_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
n_pkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
n_pkey.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
n_pkey.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
n_pkey.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
n_pkey.o: ../../include/openssl/ec.h ../../include/openssl/err.h
n_pkey.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
n_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
n_pkey.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
n_pkey.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
n_pkey.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
n_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
n_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
n_pkey.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
n_pkey.o: n_pkey.c
nsseq.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
nsseq.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
nsseq.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
nsseq.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
nsseq.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
nsseq.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
nsseq.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
nsseq.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
nsseq.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
nsseq.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
nsseq.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
nsseq.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
nsseq.o: ../../include/openssl/x509_vfy.h nsseq.c
p5_pbe.o: ../../e_os.h ../../include/openssl/asn1.h
p5_pbe.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_pbe.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
p5_pbe.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
p5_pbe.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p5_pbe.o: ../../include/openssl/ec.h ../../include/openssl/err.h
p5_pbe.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p5_pbe.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p5_pbe.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p5_pbe.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
p5_pbe.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
p5_pbe.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p5_pbe.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p5_pbe.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_pbe.o: ../include/internal/cryptlib.h p5_pbe.c
p5_pbev2.o: ../../e_os.h ../../include/openssl/asn1.h
p5_pbev2.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_pbev2.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
p5_pbev2.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
p5_pbev2.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p5_pbev2.o: ../../include/openssl/ec.h ../../include/openssl/err.h
p5_pbev2.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p5_pbev2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p5_pbev2.o: ../../include/openssl/opensslconf.h
p5_pbev2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p5_pbev2.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_pbev2.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p5_pbev2.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p5_pbev2.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p5_pbev2.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
p5_pbev2.o: p5_pbev2.c
p5_scrypt.o: ../../e_os.h ../../include/openssl/asn1.h
p5_scrypt.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_scrypt.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
p5_scrypt.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
p5_scrypt.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p5_scrypt.o: ../../include/openssl/ec.h ../../include/openssl/err.h
p5_scrypt.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p5_scrypt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p5_scrypt.o: ../../include/openssl/opensslconf.h
p5_scrypt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p5_scrypt.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_scrypt.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p5_scrypt.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p5_scrypt.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p5_scrypt.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
p5_scrypt.o: p5_scrypt.c
p8_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
p8_pkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p8_pkey.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
p8_pkey.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
p8_pkey.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
p8_pkey.o: ../../include/openssl/ec.h ../../include/openssl/err.h
p8_pkey.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p8_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p8_pkey.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p8_pkey.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
p8_pkey.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
p8_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p8_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p8_pkey.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
p8_pkey.o: p8_pkey.c
t_bitst.o: ../../e_os.h ../../include/openssl/asn1.h
t_bitst.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
t_bitst.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
t_bitst.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
t_bitst.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
t_bitst.o: ../../include/openssl/ec.h ../../include/openssl/err.h
t_bitst.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
t_bitst.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_bitst.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
t_bitst.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
t_bitst.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
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
t_spki.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
t_spki.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
t_spki.o: ../../include/openssl/ec.h ../../include/openssl/err.h
t_spki.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
t_spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_spki.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
t_spki.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
t_spki.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
t_spki.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
t_spki.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
t_spki.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
t_spki.o: t_spki.c
tasn_dec.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_dec.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tasn_dec.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
tasn_dec.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
tasn_dec.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_dec.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_dec.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_dec.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_dec.o: ../../include/openssl/symhacks.h asn1_locl.h tasn_dec.c
tasn_enc.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_enc.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_enc.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tasn_enc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_enc.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tasn_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_enc.o: ../../include/openssl/opensslconf.h
tasn_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_enc.o: ../../include/openssl/symhacks.h ../include/internal/asn1_int.h
tasn_enc.o: ../include/internal/cryptlib.h asn1_locl.h tasn_enc.c
tasn_fre.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_fre.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tasn_fre.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_fre.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_fre.o: ../../include/openssl/opensslconf.h
tasn_fre.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_fre.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_fre.o: ../../include/openssl/symhacks.h asn1_locl.h tasn_fre.c
tasn_new.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_new.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tasn_new.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_new.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tasn_new.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_new.o: ../../include/openssl/opensslconf.h
tasn_new.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_new.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_new.o: ../../include/openssl/symhacks.h asn1_locl.h tasn_new.c
tasn_prn.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_prn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_prn.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tasn_prn.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
tasn_prn.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tasn_prn.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tasn_prn.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tasn_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_prn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_prn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_prn.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
tasn_prn.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tasn_prn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tasn_prn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tasn_prn.o: ../../include/openssl/x509v3.h ../include/internal/asn1_int.h
tasn_prn.o: ../include/internal/cryptlib.h asn1_locl.h tasn_prn.c
tasn_scn.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_scn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_scn.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tasn_scn.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
tasn_scn.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
tasn_scn.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
tasn_scn.o: ../../include/openssl/err.h ../../include/openssl/evp.h
tasn_scn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_scn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
tasn_scn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_scn.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
tasn_scn.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
tasn_scn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
tasn_scn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tasn_scn.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
tasn_scn.o: asn1_locl.h tasn_scn.c
tasn_typ.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_typ.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
tasn_typ.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_typ.o: ../../include/openssl/opensslconf.h
tasn_typ.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_typ.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_typ.o: ../../include/openssl/symhacks.h tasn_typ.c
tasn_utl.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_utl.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_utl.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
tasn_utl.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
tasn_utl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tasn_utl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_utl.o: ../../include/openssl/opensslconf.h
tasn_utl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
tasn_utl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_utl.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
tasn_utl.o: asn1_locl.h tasn_utl.c
x_algor.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
x_algor.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
x_algor.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_algor.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x_algor.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_algor.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_algor.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_algor.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_algor.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_algor.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_algor.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_algor.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_algor.o: ../../include/openssl/x509_vfy.h ../include/internal/evp_int.h
x_algor.o: x_algor.c
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
x_info.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_info.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
x_info.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_info.o: ../../include/openssl/ec.h ../../include/openssl/err.h
x_info.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_info.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_info.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_info.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_info.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
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
x_pkey.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_pkey.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
x_pkey.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_pkey.o: ../../include/openssl/ec.h ../../include/openssl/err.h
x_pkey.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_pkey.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_pkey.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_pkey.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_pkey.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_pkey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_pkey.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_pkey.o: x_pkey.c
x_pubkey.o: ../../e_os.h ../../include/openssl/asn1.h
x_pubkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_pubkey.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_pubkey.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
x_pubkey.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_pubkey.o: ../../include/openssl/ec.h ../../include/openssl/err.h
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
x_sig.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_sig.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
x_sig.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_sig.o: ../../include/openssl/ec.h ../../include/openssl/err.h
x_sig.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_sig.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_sig.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_sig.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_sig.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_sig.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_sig.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_sig.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_sig.o: x_sig.c
x_spki.o: ../../e_os.h ../../include/openssl/asn1.h
x_spki.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_spki.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_spki.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
x_spki.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_spki.o: ../../include/openssl/ec.h ../../include/openssl/err.h
x_spki.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_spki.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_spki.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_spki.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_spki.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_spki.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_spki.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_spki.o: x_spki.c
x_val.o: ../../e_os.h ../../include/openssl/asn1.h
x_val.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_val.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_val.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
x_val.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_val.o: ../../include/openssl/ec.h ../../include/openssl/err.h
x_val.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_val.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_val.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_val.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_val.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_val.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_val.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_val.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_val.o: x_val.c
