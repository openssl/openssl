#
# OpenSSL/crypto/asn1/Makefile
#


CFLAGS_crypto_asn1= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_asn1=crypto/asn1/Makefile crypto/asn1/README
TEST_crypto_asn1=
APPS_crypto_asn1=

LIB_crypto_asn1=libcrypto.a
LIBSRC_crypto_asn1=	crypto/asn1/a_object.c crypto/asn1/a_bitstr.c crypto/asn1/a_utctm.c crypto/asn1/a_gentm.c crypto/asn1/a_time.c crypto/asn1/a_int.c crypto/asn1/a_octet.c \
	crypto/asn1/a_print.c crypto/asn1/a_type.c crypto/asn1/a_set.c crypto/asn1/a_dup.c crypto/asn1/a_d2i_fp.c crypto/asn1/a_i2d_fp.c \
	crypto/asn1/a_enum.c crypto/asn1/a_utf8.c crypto/asn1/a_sign.c crypto/asn1/a_digest.c crypto/asn1/a_verify.c crypto/asn1/a_mbstr.c crypto/asn1/a_strex.c \
	crypto/asn1/x_algor.c crypto/asn1/x_val.c crypto/asn1/x_pubkey.c crypto/asn1/x_sig.c crypto/asn1/x_req.c crypto/asn1/x_attrib.c crypto/asn1/x_bignum.c \
	crypto/asn1/x_long.c crypto/asn1/x_name.c crypto/asn1/x_x509.c crypto/asn1/x_x509a.c crypto/asn1/x_crl.c crypto/asn1/x_info.c crypto/asn1/x_spki.c crypto/asn1/nsseq.c \
	crypto/asn1/x_nx509.c crypto/asn1/d2i_pu.c crypto/asn1/d2i_pr.c crypto/asn1/i2d_pu.c crypto/asn1/i2d_pr.c\
	crypto/asn1/t_req.c crypto/asn1/t_x509.c crypto/asn1/t_x509a.c crypto/asn1/t_crl.c crypto/asn1/t_pkey.c crypto/asn1/t_spki.c crypto/asn1/t_bitst.c \
	crypto/asn1/tasn_new.c crypto/asn1/tasn_fre.c crypto/asn1/tasn_enc.c crypto/asn1/tasn_dec.c crypto/asn1/tasn_utl.c crypto/asn1/tasn_typ.c \
	crypto/asn1/tasn_prn.c crypto/asn1/tasn_scn.c crypto/asn1/ameth_lib.c \
	crypto/asn1/f_int.c crypto/asn1/f_string.c crypto/asn1/n_pkey.c \
	crypto/asn1/f_enum.c crypto/asn1/x_pkey.c crypto/asn1/a_bool.c crypto/asn1/x_exten.c crypto/asn1/bio_asn1.c crypto/asn1/bio_ndef.c crypto/asn1/asn_mime.c \
	crypto/asn1/asn1_gen.c crypto/asn1/asn1_par.c crypto/asn1/asn1_lib.c crypto/asn1/asn1_err.c crypto/asn1/a_bytes.c crypto/asn1/a_strnid.c \
	crypto/asn1/evp_asn1.c crypto/asn1/asn_pack.c crypto/asn1/p5_pbe.c crypto/asn1/p5_pbev2.c crypto/asn1/p8_pkey.c crypto/asn1/asn_moid.c \
	crypto/asn1/asn_mstbl.c
LIBOBJ_crypto_asn1= crypto/asn1/a_object.o crypto/asn1/a_bitstr.o crypto/asn1/a_utctm.o crypto/asn1/a_gentm.o crypto/asn1/a_time.o crypto/asn1/a_int.o crypto/asn1/a_octet.o \
	crypto/asn1/a_print.o crypto/asn1/a_type.o crypto/asn1/a_set.o crypto/asn1/a_dup.o crypto/asn1/a_d2i_fp.o crypto/asn1/a_i2d_fp.o \
	crypto/asn1/a_enum.o crypto/asn1/a_utf8.o crypto/asn1/a_sign.o crypto/asn1/a_digest.o crypto/asn1/a_verify.o crypto/asn1/a_mbstr.o crypto/asn1/a_strex.o \
	crypto/asn1/x_algor.o crypto/asn1/x_val.o crypto/asn1/x_pubkey.o crypto/asn1/x_sig.o crypto/asn1/x_req.o crypto/asn1/x_attrib.o crypto/asn1/x_bignum.o \
	crypto/asn1/x_long.o crypto/asn1/x_name.o crypto/asn1/x_x509.o crypto/asn1/x_x509a.o crypto/asn1/x_crl.o crypto/asn1/x_info.o crypto/asn1/x_spki.o crypto/asn1/nsseq.o \
	crypto/asn1/x_nx509.o crypto/asn1/d2i_pu.o crypto/asn1/d2i_pr.o crypto/asn1/i2d_pu.o crypto/asn1/i2d_pr.o \
	crypto/asn1/t_req.o crypto/asn1/t_x509.o crypto/asn1/t_x509a.o crypto/asn1/t_crl.o crypto/asn1/t_pkey.o crypto/asn1/t_spki.o crypto/asn1/t_bitst.o \
	crypto/asn1/tasn_new.o crypto/asn1/tasn_fre.o crypto/asn1/tasn_enc.o crypto/asn1/tasn_dec.o crypto/asn1/tasn_utl.o crypto/asn1/tasn_typ.o \
	crypto/asn1/tasn_prn.o crypto/asn1/tasn_scn.o crypto/asn1/ameth_lib.o \
	crypto/asn1/f_int.o crypto/asn1/f_string.o crypto/asn1/n_pkey.o \
	crypto/asn1/f_enum.o crypto/asn1/x_pkey.o crypto/asn1/a_bool.o crypto/asn1/x_exten.o crypto/asn1/bio_asn1.o crypto/asn1/bio_ndef.o crypto/asn1/asn_mime.o \
	crypto/asn1/asn1_gen.o crypto/asn1/asn1_par.o crypto/asn1/asn1_lib.o crypto/asn1/asn1_err.o crypto/asn1/a_bytes.o crypto/asn1/a_strnid.o \
	crypto/asn1/evp_asn1.o crypto/asn1/asn_pack.o crypto/asn1/p5_pbe.o crypto/asn1/p5_pbev2.o crypto/asn1/p8_pkey.o crypto/asn1/asn_moid.o \
	crypto/asn1/asn_mstbl.o

SRC_crypto_asn1= $(LIBSRC_crypto_asn1)

EXHEADER_crypto_asn1=  crypto/asn1/asn1.h crypto/asn1/asn1_mac.h crypto/asn1/asn1t.h
HEADER_crypto_asn1=	$(EXHEADER_crypto_asn1) crypto/asn1/asn1_locl.h

ALL_crypto_asn1=    $(GENERAL_crypto_asn1) $(SRC_crypto_asn1) $(HEADER_crypto_asn1)

crypto/asn1/pk:	crypto/asn1/pk.c
	cc -g -Iinclude -c crypto/asn1/pk.c
	cc -g -Iinclude -o crypto/asn1/pk crypto/asn1/pk.o -L. -lcrypto

all: all_crypto_asn1
all_crypto_asn1:	crypto/asn1/lib

crypto/asn1/lib:	$(LIBOBJ_crypto_asn1)
	$(ARX) $(LIB_crypto_asn1) $(LIBOBJ_crypto_asn1)
	$(RANLIB) $(LIB_crypto_asn1) || echo Never mind.
	@touch crypto/asn1/lib

files: files_crypto_asn1
files_crypto_asn1:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_asn1
links_crypto_asn1:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_asn1)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_asn1)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_asn1)

install: install_crypto_asn1
install_crypto_asn1:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_asn1)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_asn1
tags_crypto_asn1:
	ctags $(SRC_crypto_asn1)

tests: tests_crypto_asn1
tests_crypto_asn1:

lint: lint_crypto_asn1
lint_crypto_asn1:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_asn1)>crypto/asn1/fluff

dclean: dclean_crypto_asn1
dclean_crypto_asn1:

clean: clean_crypto_asn1
clean_crypto_asn1:
	rm -f crypto/asn1/*.o crypto/asn1/*.d crypto/asn1/*.obj crypto/asn1/lib crypto/asn1/tags crypto/asn1/core crypto/asn1/.pure crypto/asn1/.nfs* crypto/asn1/*.old crypto/asn1/*.bak crypto/asn1/fluff


