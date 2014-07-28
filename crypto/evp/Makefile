#
# OpenSSL/crypto/evp/Makefile
#

DIR_crypto_evp=	evp
INCLUDES_crypto_evp= -I.. -I$(TOP_crypto_evp) -I../../include

CFLAGS_crypto_evp= $(INCLUDES_crypto_evp) $(CFLAG)

GENERAL_crypto_evp=Makefile
TEST_crypto_evp=evp_test.c p5_crpt2_test.c
TESTDATA=evptests.txt
APPS_crypto_evp=

LIB_crypto_evp=$(TOP_crypto_evp)/libcrypto.a
LIBSRC_crypto_evp= encode.c digest.c evp_enc.c evp_key.c evp_acnf.c evp_cnf.c \
	e_des.c e_bf.c e_idea.c e_des3.c e_camellia.c\
	e_rc4.c e_aes.c names.c e_seed.c \
	e_xcbc_d.c e_rc2.c e_cast.c e_rc5.c \
	m_null.c m_md2.c m_md4.c m_md5.c m_sha.c m_sha1.c m_wp.c \
	m_dss.c m_dss1.c m_mdc2.c m_ripemd.c m_ecdsa.c\
	p_open.c p_seal.c p_sign.c p_verify.c p_lib.c p_enc.c p_dec.c \
	bio_md.c bio_b64.c bio_enc.c evp_err.c e_null.c \
	c_all.c c_allc.c c_alld.c evp_lib.c bio_ok.c \
	evp_pkey.c evp_pbe.c p5_crpt.c p5_crpt2.c \
	e_old.c pmeth_lib.c pmeth_fn.c pmeth_gn.c m_sigver.c \
	e_aes_cbc_hmac_sha1.c e_aes_cbc_hmac_sha256.c e_rc4_hmac_md5.c

LIBOBJ_crypto_evp=	encode.o digest.o evp_enc.o evp_key.o evp_acnf.o evp_cnf.o \
	e_des.o e_bf.o e_idea.o e_des3.o e_camellia.o\
	e_rc4.o e_aes.o names.o e_seed.o \
	e_xcbc_d.o e_rc2.o e_cast.o e_rc5.o \
	m_null.o m_md2.o m_md4.o m_md5.o m_sha.o m_sha1.o m_wp.o \
	m_dss.o m_dss1.o m_mdc2.o m_ripemd.o m_ecdsa.o\
	p_open.o p_seal.o p_sign.o p_verify.o p_lib.o p_enc.o p_dec.o \
	bio_md.o bio_b64.o bio_enc.o evp_err.o e_null.o \
	c_all.o c_allc.o c_alld.o evp_lib.o bio_ok.o \
	evp_pkey.o evp_pbe.o p5_crpt.o p5_crpt2.o \
	e_old.o pmeth_lib.o pmeth_fn.o pmeth_gn.o m_sigver.o \
	e_aes_cbc_hmac_sha1.o e_aes_cbc_hmac_sha256.o e_rc4_hmac_md5.o

SRC_crypto_evp= $(LIBSRC_crypto_evp)

EXHEADER_crypto_evp= evp.h
HEADER_crypto_evp=	evp_locl.h $(EXHEADER_crypto_evp)

ALL_crypto_evp=    $(GENERAL_crypto_evp) $(SRC_crypto_evp) $(HEADER_crypto_evp)

top: top_crypto_evp
top_crypto_evp:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_evp) sub_all)

all: all_crypto_evp
all_crypto_evp:	lib

lib:	$(LIBOBJ_crypto_evp)
	$(ARX) $(LIB_crypto_evp) $(LIBOBJ_crypto_evp)
	$(RANLIB) $(LIB_crypto_evp) || echo Never mind.
	@touch lib

files: files_crypto_evp
files_crypto_evp:
	$(PERL) $(TOP_crypto_evp)/util/files.pl TOP=$(TOP_crypto_evp) Makefile >> $(TOP_crypto_evp)/MINFO

links: links_crypto_evp
links_crypto_evp:
	@$(PERL) $(TOP_crypto_evp)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_evp)
	@$(PERL) $(TOP_crypto_evp)/util/mklink.pl ../../test $(TEST_crypto_evp)
	@[ -f $(TESTDATA) ] && cp $(TESTDATA) ../../test && echo "$(TESTDATA) -> ../../test/$(TESTDATA)"
	@$(PERL) $(TOP_crypto_evp)/util/mklink.pl ../../apps $(APPS_crypto_evp)

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
	lint -DLINT $(INCLUDES_crypto_evp) $(SRC_crypto_evp)>fluff

dclean: dclean_crypto_evp
dclean_crypto_evp:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_evp
clean_crypto_evp:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_evp) $(CPPFLAGS) -c -o $@ $<
