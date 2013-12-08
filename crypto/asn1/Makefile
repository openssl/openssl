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
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	a_object.c a_bitstr.c a_utctm.c a_gentm.c a_time.c a_int.c a_octet.c \
	a_print.c a_type.c a_set.c a_dup.c a_d2i_fp.c a_i2d_fp.c \
	a_enum.c a_utf8.c a_sign.c a_digest.c a_verify.c a_mbstr.c a_strex.c \
	x_algor.c x_val.c x_pubkey.c x_sig.c x_req.c x_attrib.c x_bignum.c \
	x_long.c x_name.c x_x509.c x_x509a.c x_crl.c x_info.c x_spki.c nsseq.c \
	x_nx509.c d2i_pu.c d2i_pr.c i2d_pu.c i2d_pr.c\
	t_req.c t_x509.c t_x509a.c t_crl.c t_pkey.c t_spki.c t_bitst.c \
	tasn_new.c tasn_fre.c tasn_enc.c tasn_dec.c tasn_utl.c tasn_typ.c \
	tasn_prn.c ameth_lib.c \
	f_int.c f_string.c n_pkey.c \
	f_enum.c x_pkey.c a_bool.c x_exten.c bio_asn1.c bio_ndef.c asn_mime.c \
	asn1_gen.c asn1_par.c asn1_lib.c asn1_err.c a_bytes.c a_strnid.c \
	evp_asn1.c asn_pack.c p5_pbe.c p5_pbev2.c p8_pkey.c asn_moid.c
LIBOBJ= a_object.o a_bitstr.o a_utctm.o a_gentm.o a_time.o a_int.o a_octet.o \
	a_print.o a_type.o a_set.o a_dup.o a_d2i_fp.o a_i2d_fp.o \
	a_enum.o a_utf8.o a_sign.o a_digest.o a_verify.o a_mbstr.o a_strex.o \
	x_algor.o x_val.o x_pubkey.o x_sig.o x_req.o x_attrib.o x_bignum.o \
	x_long.o x_name.o x_x509.o x_x509a.o x_crl.o x_info.o x_spki.o nsseq.o \
	x_nx509.o d2i_pu.o d2i_pr.o i2d_pu.o i2d_pr.o \
	t_req.o t_x509.o t_x509a.o t_crl.o t_pkey.o t_spki.o t_bitst.o \
	tasn_new.o tasn_fre.o tasn_enc.o tasn_dec.o tasn_utl.o tasn_typ.o \
	tasn_prn.o ameth_lib.o \
	f_int.o f_string.o n_pkey.o \
	f_enum.o x_pkey.o a_bool.o x_exten.o bio_asn1.o bio_ndef.o asn_mime.o \
	asn1_gen.o asn1_par.o asn1_lib.o asn1_err.o a_bytes.o a_strnid.o \
	evp_asn1.o asn_pack.o p5_pbe.o p5_pbev2.o p8_pkey.o asn_moid.o

SRC= $(LIBSRC)

EXHEADER=  asn1.h asn1_mac.h asn1t.h
HEADER=	$(EXHEADER) asn1_locl.h

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
	@[ -n "$(MAKEDEPEND)" ] # should be set by top Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff


# DO NOT DELETE THIS LINE -- make depend depends on it.

a_bitstr.o: ../../e_os.h ../../include/openssl/asn1.h
a_bitstr.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_bitstr.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_bitstr.o: ../../include/openssl/stack.h ../cryptlib.h a_bitstr.c
a_bool.o: ../../e_os.h ../../include/openssl/asn1.h
a_bool.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_bool.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_bool.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_bool.o: ../cryptlib.h a_bool.c
a_bytes.o: ../../e_os.h ../../include/openssl/asn1.h
a_bytes.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_bytes.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_bytes.o: ../../include/openssl/stack.h ../cryptlib.h a_bytes.c
a_d2i_fp.o: ../../e_os.h ../../include/openssl/asn1.h
a_d2i_fp.o: ../../include/openssl/asn1_mac.h ../../include/openssl/bio.h
a_d2i_fp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_d2i_fp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_d2i_fp.o: ../cryptlib.h a_d2i_fp.c
a_digest.o: ../../e_os.h ../../include/openssl/asn1.h
a_digest.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_digest.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_digest.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
a_digest.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_digest.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_digest.o: ../cryptlib.h a_digest.c
a_dup.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_dup.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_dup.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_dup.o: ../cryptlib.h a_dup.c
a_enum.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_enum.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_enum.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_enum.o: ../cryptlib.h a_enum.c
a_gentm.o: ../../e_os.h ../../include/openssl/asn1.h
a_gentm.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_gentm.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_gentm.o: ../../include/openssl/stack.h ../cryptlib.h ../o_time.h a_gentm.c
a_i2d_fp.o: ../../e_os.h ../../include/openssl/asn1.h
a_i2d_fp.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_i2d_fp.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_i2d_fp.o: ../../include/openssl/stack.h ../cryptlib.h a_i2d_fp.c
a_int.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_int.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_int.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_int.o: ../cryptlib.h a_int.c
a_mbstr.o: ../../e_os.h ../../include/openssl/asn1.h
a_mbstr.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_mbstr.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_mbstr.o: ../../include/openssl/stack.h ../cryptlib.h a_mbstr.c
a_object.o: ../../e_os.h ../../include/openssl/asn1.h
a_object.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_object.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_object.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
a_object.o: ../../include/openssl/stack.h ../cryptlib.h a_object.c
a_octet.o: ../../e_os.h ../../include/openssl/asn1.h
a_octet.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_octet.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_octet.o: ../../include/openssl/stack.h ../cryptlib.h a_octet.c
a_print.o: ../../e_os.h ../../include/openssl/asn1.h
a_print.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_print.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_print.o: ../../include/openssl/stack.h ../cryptlib.h a_print.c
a_set.o: ../../e_os.h ../../include/openssl/asn1.h
a_set.o: ../../include/openssl/asn1_mac.h ../../include/openssl/bio.h
a_set.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_set.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_set.o: ../cryptlib.h a_set.c
a_sign.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_sign.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_sign.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_sign.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
a_sign.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
a_sign.o: ../../include/openssl/x509_vfy.h ../cryptlib.h a_sign.c asn1_locl.h
a_strex.o: ../../e_os.h ../../include/openssl/asn1.h
a_strex.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_strex.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_strex.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
a_strex.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_strex.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_strex.o: ../cryptlib.h a_strex.c charmap.h
a_strnid.o: ../../e_os.h ../../include/openssl/asn1.h
a_strnid.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_strnid.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_strnid.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
a_strnid.o: ../../include/openssl/stack.h ../cryptlib.h a_strnid.c
a_time.o: ../../e_os.h ../../include/openssl/asn1.h
a_time.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_time.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_time.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_time.o: ../cryptlib.h ../o_time.h a_time.c
a_type.o: ../../e_os.h ../../include/openssl/asn1.h
a_type.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
a_type.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_type.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
a_type.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_type.o: ../cryptlib.h a_type.c
a_utctm.o: ../../e_os.h ../../include/openssl/asn1.h
a_utctm.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_utctm.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
a_utctm.o: ../../include/openssl/stack.h ../cryptlib.h ../o_time.h a_utctm.c
a_utf8.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
a_utf8.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
a_utf8.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_utf8.o: ../cryptlib.h a_utf8.c
a_verify.o: ../../e_os.h ../../include/openssl/asn1.h
a_verify.o: ../../include/openssl/bio.h ../../include/openssl/err.h
a_verify.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
a_verify.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
a_verify.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
a_verify.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
a_verify.o: ../cryptlib.h a_verify.c asn1_locl.h
ameth_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ameth_lib.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
ameth_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
ameth_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ameth_lib.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
ameth_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ameth_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ameth_lib.o: ../cryptlib.h ameth_lib.c asn1_locl.h
asn1_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
asn1_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn1_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_err.o: asn1_err.c
asn1_gen.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_gen.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
asn1_gen.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn1_gen.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn1_gen.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
asn1_gen.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
asn1_gen.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
asn1_gen.o: ../cryptlib.h asn1_gen.c
asn1_lib.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_lib.o: ../../include/openssl/asn1_mac.h ../../include/openssl/bio.h
asn1_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn1_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn1_lib.o: ../cryptlib.h asn1_lib.c
asn1_par.o: ../../e_os.h ../../include/openssl/asn1.h
asn1_par.o: ../../include/openssl/bio.h ../../include/openssl/err.h
asn1_par.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn1_par.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
asn1_par.o: ../../include/openssl/stack.h ../cryptlib.h asn1_par.c
asn_mime.o: ../../e_os.h ../../include/openssl/asn1.h
asn_mime.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
asn_mime.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
asn_mime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
asn_mime.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
asn_mime.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn_mime.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
asn_mime.o: ../cryptlib.h asn1_locl.h asn_mime.c
asn_moid.o: ../../e_os.h ../../include/openssl/asn1.h
asn_moid.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
asn_moid.o: ../../include/openssl/dso.h ../../include/openssl/err.h
asn_moid.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
asn_moid.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
asn_moid.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
asn_moid.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
asn_moid.o: ../cryptlib.h asn_moid.c
asn_pack.o: ../../e_os.h ../../include/openssl/asn1.h
asn_pack.o: ../../include/openssl/bio.h ../../include/openssl/err.h
asn_pack.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
asn_pack.o: ../../include/openssl/stack.h ../cryptlib.h asn_pack.c
bio_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bio_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bio_asn1.o: bio_asn1.c
bio_ndef.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
bio_ndef.o: ../../include/openssl/bio.h ../../include/openssl/err.h
bio_ndef.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bio_ndef.o: ../../include/openssl/stack.h bio_ndef.c
d2i_pr.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
d2i_pr.o: ../../include/openssl/engine.h ../../include/openssl/err.h
d2i_pr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
d2i_pr.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
d2i_pr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
d2i_pr.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
d2i_pr.o: ../cryptlib.h asn1_locl.h d2i_pr.c
d2i_pu.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
d2i_pu.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
d2i_pu.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
d2i_pu.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
d2i_pu.o: ../cryptlib.h d2i_pu.c
evp_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
evp_asn1.o: ../../include/openssl/asn1_mac.h ../../include/openssl/bio.h
evp_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
evp_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
evp_asn1.o: ../cryptlib.h evp_asn1.c
f_enum.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
f_enum.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
f_enum.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
f_enum.o: ../cryptlib.h f_enum.c
f_int.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
f_int.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
f_int.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
f_int.o: ../cryptlib.h f_int.c
f_string.o: ../../e_os.h ../../include/openssl/asn1.h
f_string.o: ../../include/openssl/bio.h ../../include/openssl/err.h
f_string.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
f_string.o: ../../include/openssl/stack.h ../cryptlib.h f_string.c
i2d_pr.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
i2d_pr.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
i2d_pr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
i2d_pr.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
i2d_pr.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
i2d_pr.o: ../../include/openssl/x509_vfy.h ../cryptlib.h asn1_locl.h i2d_pr.c
i2d_pu.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
i2d_pu.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
i2d_pu.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
i2d_pu.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
i2d_pu.o: ../cryptlib.h i2d_pu.c
n_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
n_pkey.o: ../../include/openssl/asn1_mac.h ../../include/openssl/asn1t.h
n_pkey.o: ../../include/openssl/bio.h ../../include/openssl/err.h
n_pkey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
n_pkey.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
n_pkey.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
n_pkey.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
n_pkey.o: ../cryptlib.h n_pkey.c
nsseq.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
nsseq.o: ../../include/openssl/bio.h ../../include/openssl/lhash.h
nsseq.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
nsseq.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
nsseq.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
nsseq.o: ../../include/openssl/x509_vfy.h nsseq.c
p5_pbe.o: ../../e_os.h ../../include/openssl/asn1.h
p5_pbe.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_pbe.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p5_pbe.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p5_pbe.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_pbe.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p5_pbe.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_pbe.o: ../cryptlib.h p5_pbe.c
p5_pbev2.o: ../../e_os.h ../../include/openssl/asn1.h
p5_pbev2.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p5_pbev2.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p5_pbev2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p5_pbev2.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
p5_pbev2.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
p5_pbev2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p5_pbev2.o: ../cryptlib.h p5_pbev2.c
p8_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
p8_pkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p8_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
p8_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p8_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p8_pkey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
p8_pkey.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p8_pkey.c
t_bitst.o: ../../e_os.h ../../include/openssl/asn1.h
t_bitst.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
t_bitst.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
t_bitst.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_bitst.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
t_bitst.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
t_bitst.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
t_bitst.o: ../cryptlib.h t_bitst.c
t_crl.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_crl.o: ../../include/openssl/conf.h ../../include/openssl/err.h
t_crl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_crl.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
t_crl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
t_crl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
t_crl.o: ../../include/openssl/x509v3.h ../cryptlib.h t_crl.c
t_pkey.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
t_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_pkey.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
t_pkey.o: ../cryptlib.h t_pkey.c
t_req.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_req.o: ../../include/openssl/conf.h ../../include/openssl/err.h
t_req.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_req.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
t_req.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
t_req.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
t_req.o: ../../include/openssl/x509v3.h ../cryptlib.h t_req.c
t_spki.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_spki.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
t_spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
t_spki.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
t_spki.o: ../../include/openssl/x509_vfy.h ../cryptlib.h t_spki.c
t_x509.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_x509.o: ../../include/openssl/conf.h ../../include/openssl/err.h
t_x509.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_x509.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
t_x509.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
t_x509.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
t_x509.o: ../../include/openssl/x509v3.h ../cryptlib.h asn1_locl.h t_x509.c
t_x509a.o: ../../e_os.h ../../include/openssl/asn1.h
t_x509a.o: ../../include/openssl/bio.h ../../include/openssl/err.h
t_x509a.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_x509a.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
t_x509a.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
t_x509a.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
t_x509a.o: ../cryptlib.h t_x509a.c
tasn_dec.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_dec.o: ../../include/openssl/bio.h ../../include/openssl/err.h
tasn_dec.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_dec.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
tasn_dec.o: ../../include/openssl/stack.h tasn_dec.c
tasn_enc.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_enc.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_enc.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
tasn_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
tasn_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_enc.o: ../cryptlib.h tasn_enc.c
tasn_fre.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_fre.o: ../../include/openssl/bio.h ../../include/openssl/obj_mac.h
tasn_fre.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
tasn_fre.o: ../../include/openssl/stack.h tasn_fre.c
tasn_new.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_new.o: ../../include/openssl/bio.h ../../include/openssl/err.h
tasn_new.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_new.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
tasn_new.o: ../../include/openssl/stack.h tasn_new.c
tasn_prn.o: ../../e_os.h ../../include/openssl/asn1.h
tasn_prn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
tasn_prn.o: ../../include/openssl/conf.h ../../include/openssl/err.h
tasn_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_prn.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
tasn_prn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
tasn_prn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
tasn_prn.o: ../../include/openssl/x509v3.h ../cryptlib.h asn1_locl.h tasn_prn.c
tasn_typ.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_typ.o: ../../include/openssl/bio.h ../../include/openssl/safestack.h
tasn_typ.o: ../../include/openssl/stack.h tasn_typ.c
tasn_utl.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
tasn_utl.o: ../../include/openssl/bio.h ../../include/openssl/err.h
tasn_utl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
tasn_utl.o: ../../include/openssl/objects.h ../../include/openssl/safestack.h
tasn_utl.o: ../../include/openssl/stack.h tasn_utl.c
x_algor.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
x_algor.o: ../../include/openssl/bio.h ../../include/openssl/lhash.h
x_algor.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_algor.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_algor.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_algor.o: ../../include/openssl/x509_vfy.h x_algor.c
x_attrib.o: ../../e_os.h ../../include/openssl/asn1.h
x_attrib.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_attrib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_attrib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_attrib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_attrib.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_attrib.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_attrib.c
x_bignum.o: ../../e_os.h ../../include/openssl/asn1.h
x_bignum.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_bignum.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_bignum.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
x_bignum.o: ../cryptlib.h x_bignum.c
x_crl.o: ../../e_os.h ../../include/openssl/asn1.h
x_crl.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_crl.o: ../../include/openssl/conf.h ../../include/openssl/err.h
x_crl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_crl.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
x_crl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
x_crl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x_crl.o: ../../include/openssl/x509v3.h ../cryptlib.h asn1_locl.h x_crl.c
x_exten.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
x_exten.o: ../../include/openssl/bio.h ../../include/openssl/lhash.h
x_exten.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_exten.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_exten.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_exten.o: ../../include/openssl/x509_vfy.h x_exten.c
x_info.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_info.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_info.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_info.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_info.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_info.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_info.c
x_long.o: ../../e_os.h ../../include/openssl/asn1.h
x_long.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_long.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_long.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
x_long.o: ../cryptlib.h x_long.c
x_name.o: ../../e_os.h ../../include/openssl/asn1.h
x_name.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_name.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_name.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_name.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_name.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_name.o: ../../include/openssl/x509_vfy.h ../cryptlib.h asn1_locl.h x_name.c
x_nx509.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
x_nx509.o: ../../include/openssl/bio.h ../../include/openssl/lhash.h
x_nx509.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_nx509.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_nx509.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_nx509.o: ../../include/openssl/x509_vfy.h x_nx509.c
x_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
x_pkey.o: ../../include/openssl/asn1_mac.h ../../include/openssl/bio.h
x_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_pkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_pkey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_pkey.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_pkey.c
x_pubkey.o: ../../e_os.h ../../include/openssl/asn1.h
x_pubkey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_pubkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_pubkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_pubkey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_pubkey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_pubkey.o: ../../include/openssl/x509_vfy.h ../cryptlib.h asn1_locl.h
x_pubkey.o: x_pubkey.c
x_req.o: ../../e_os.h ../../include/openssl/asn1.h
x_req.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_req.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_req.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_req.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_req.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_req.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_req.c
x_sig.o: ../../e_os.h ../../include/openssl/asn1.h
x_sig.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_sig.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_sig.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_sig.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_sig.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_sig.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_sig.c
x_spki.o: ../../e_os.h ../../include/openssl/asn1.h
x_spki.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_spki.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_spki.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_spki.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_spki.c
x_val.o: ../../e_os.h ../../include/openssl/asn1.h
x_val.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_val.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_val.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_val.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_val.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_val.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_val.c
x_x509.o: ../../e_os.h ../../include/openssl/asn1.h
x_x509.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_x509.o: ../../include/openssl/conf.h ../../include/openssl/err.h
x_x509.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_x509.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
x_x509.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
x_x509.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x_x509.o: ../../include/openssl/x509v3.h ../cryptlib.h x_x509.c
x_x509a.o: ../../e_os.h ../../include/openssl/asn1.h
x_x509a.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_x509a.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
x_x509a.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_x509a.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_x509a.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
x_x509a.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_x509a.c
