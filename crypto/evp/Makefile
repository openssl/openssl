#
# OpenSSL/crypto/evp/Makefile
#

INCLUDES_crypto_evp= -Icrypto -I. -Iinclude

CFLAGS_crypto_evp= $(INCLUDES_crypto_evp) $(CFLAG)

GENERAL_crypto_evp=crypto/evp/Makefile
TEST_crypto_evp=crypto/evp/evp_test.c crypto/evp/p5_crpt2_test.c
TESTDATA=crypto/evp/evptests.txt
APPS_crypto_evp=

LIB_crypto_evp=libcrypto.a
LIBSRC_crypto_evp= crypto/evp/encode.c crypto/evp/digest.c crypto/evp/evp_enc.c crypto/evp/evp_key.c crypto/evp/evp_acnf.c crypto/evp/evp_cnf.c \
	crypto/evp/e_des.c crypto/evp/e_bf.c crypto/evp/e_idea.c crypto/evp/e_des3.c crypto/evp/e_camellia.c\
	crypto/evp/e_rc4.c crypto/evp/e_aes.c crypto/evp/names.c crypto/evp/e_seed.c \
	crypto/evp/e_xcbc_d.c crypto/evp/e_rc2.c crypto/evp/e_cast.c crypto/evp/e_rc5.c \
	crypto/evp/m_null.c crypto/evp/m_md2.c crypto/evp/m_md4.c crypto/evp/m_md5.c crypto/evp/m_sha.c crypto/evp/m_sha1.c crypto/evp/m_wp.c \
	crypto/evp/m_dss.c crypto/evp/m_dss1.c crypto/evp/m_mdc2.c crypto/evp/m_ripemd.c crypto/evp/m_ecdsa.c\
	crypto/evp/p_open.c crypto/evp/p_seal.c crypto/evp/p_sign.c crypto/evp/p_verify.c crypto/evp/p_lib.c crypto/evp/p_enc.c crypto/evp/p_dec.c \
	crypto/evp/bio_md.c crypto/evp/bio_b64.c crypto/evp/bio_enc.c crypto/evp/evp_err.c crypto/evp/e_null.c \
	crypto/evp/c_all.c crypto/evp/c_allc.c crypto/evp/c_alld.c crypto/evp/evp_lib.c crypto/evp/bio_ok.c \
	crypto/evp/evp_pkey.c crypto/evp/evp_pbe.c crypto/evp/p5_crpt.c crypto/evp/p5_crpt2.c \
	crypto/evp/e_old.c crypto/evp/pmeth_lib.c crypto/evp/pmeth_fn.c crypto/evp/pmeth_gn.c crypto/evp/m_sigver.c \
	crypto/evp/e_aes_cbc_hmac_sha1.c crypto/evp/e_aes_cbc_hmac_sha256.c crypto/evp/e_rc4_hmac_md5.c

LIBOBJ_crypto_evp=	crypto/evp/encode.o crypto/evp/digest.o crypto/evp/evp_enc.o crypto/evp/evp_key.o crypto/evp/evp_acnf.o crypto/evp/evp_cnf.o \
	crypto/evp/e_des.o crypto/evp/e_bf.o crypto/evp/e_idea.o crypto/evp/e_des3.o crypto/evp/e_camellia.o\
	crypto/evp/e_rc4.o crypto/evp/e_aes.o crypto/evp/names.o crypto/evp/e_seed.o \
	crypto/evp/e_xcbc_d.o crypto/evp/e_rc2.o crypto/evp/e_cast.o crypto/evp/e_rc5.o \
	crypto/evp/m_null.o crypto/evp/m_md2.o crypto/evp/m_md4.o crypto/evp/m_md5.o crypto/evp/m_sha.o crypto/evp/m_sha1.o crypto/evp/m_wp.o \
	crypto/evp/m_dss.o crypto/evp/m_dss1.o crypto/evp/m_mdc2.o crypto/evp/m_ripemd.o crypto/evp/m_ecdsa.o\
	crypto/evp/p_open.o crypto/evp/p_seal.o crypto/evp/p_sign.o crypto/evp/p_verify.o crypto/evp/p_lib.o crypto/evp/p_enc.o crypto/evp/p_dec.o \
	crypto/evp/bio_md.o crypto/evp/bio_b64.o crypto/evp/bio_enc.o crypto/evp/evp_err.o crypto/evp/e_null.o \
	crypto/evp/c_all.o crypto/evp/c_allc.o crypto/evp/c_alld.o crypto/evp/evp_lib.o crypto/evp/bio_ok.o \
	crypto/evp/evp_pkey.o crypto/evp/evp_pbe.o crypto/evp/p5_crpt.o crypto/evp/p5_crpt2.o \
	crypto/evp/e_old.o crypto/evp/pmeth_lib.o crypto/evp/pmeth_fn.o crypto/evp/pmeth_gn.o crypto/evp/m_sigver.o \
	crypto/evp/e_aes_cbc_hmac_sha1.o crypto/evp/e_aes_cbc_hmac_sha256.o crypto/evp/e_rc4_hmac_md5.o

SRC_crypto_evp= $(LIBSRC_crypto_evp)

EXHEADER_crypto_evp= crypto/evp/evp.h
HEADER_crypto_evp=	crypto/evp/evp_locl.h $(EXHEADER_crypto_evp)

ALL_crypto_evp=    $(GENERAL_crypto_evp) $(SRC_crypto_evp) $(HEADER_crypto_evp)


all: all_crypto_evp
all_crypto_evp:	crypto/evp/lib

crypto/evp/lib:	$(LIBOBJ_crypto_evp)
	$(ARX) $(LIB_crypto_evp) $(LIBOBJ_crypto_evp)
	$(RANLIB) $(LIB_crypto_evp) || echo Never mind.
	@touch crypto/evp/lib

files: files_crypto_evp
files_crypto_evp:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_evp
links_crypto_evp:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_evp)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_evp)
	@[ -f $(TESTDATA) ] && cp $(TESTDATA) ./test && echo "$(TESTDATA) -> $(TESTDATA)"
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_evp)

install: install_crypto_evp
install_crypto_evp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_evp)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_evp
tags_crypto_evp:
	ctags $(SRC_crypto_evp)

tests: tests_crypto_evp
tests_crypto_evp:

lint: lint_crypto_evp
lint_crypto_evp:
	lint -DLINT $(INCLUDES_crypto_evp) $(SRC_crypto_evp)>crypto/evp/fluff

dclean: dclean_crypto_evp
dclean_crypto_evp:

clean: clean_crypto_evp
clean_crypto_evp:
	rm -f crypto/evp/*.o crypto/evp/*.d crypto/evp/*.obj crypto/evp/lib crypto/evp/tags crypto/evp/core crypto/evp/.pure crypto/evp/.nfs* crypto/evp/*.old crypto/evp/*.bak crypto/evp/fluff

