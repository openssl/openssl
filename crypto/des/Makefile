#
# OpenSSL/crypto/des/Makefile
#

CPP_crypto_des=	$(CC) -E

CFLAGS_crypto_des= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_des= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_des= $(ASFLAGS_crypto_des)

GENERAL_crypto_des=crypto/des/Makefile
TEST_crypto_des=crypto/des/destest.c
APPS_crypto_des=

LIB_crypto_des=libcrypto.a
LIBSRC_crypto_des=	crypto/des/cbc_cksm.c crypto/des/cbc_enc.c  crypto/des/cfb64enc.c crypto/des/cfb_enc.c  \
	crypto/des/ecb3_enc.c crypto/des/ecb_enc.c  crypto/des/enc_read.c crypto/des/enc_writ.c \
	crypto/des/fcrypt.c crypto/des/ofb64enc.c crypto/des/ofb_enc.c  crypto/des/pcbc_enc.c \
	crypto/des/qud_cksm.c crypto/des/rand_key.c crypto/des/rpc_enc.c  crypto/des/set_key.c  \
	crypto/des/des_enc.c crypto/des/fcrypt_b.c \
	crypto/des/xcbc_enc.c \
	crypto/des/str2key.c  crypto/des/cfb64ede.c crypto/des/ofb64ede.c crypto/des/ede_cbcm_enc.c crypto/des/des_old.c crypto/des/des_old2.c \
	crypto/des/read2pwd.c

LIBOBJ_crypto_des= crypto/des/set_key.o  crypto/des/ecb_enc.o  crypto/des/cbc_enc.o \
	crypto/des/ecb3_enc.o crypto/des/cfb64enc.o crypto/des/cfb64ede.o crypto/des/cfb_enc.o  crypto/des/ofb64ede.o \
	crypto/des/enc_read.o crypto/des/enc_writ.o crypto/des/ofb64enc.o \
	crypto/des/ofb_enc.o  crypto/des/str2key.o  crypto/des/pcbc_enc.o crypto/des/qud_cksm.o crypto/des/rand_key.o \
	${DES_ENC} \
	crypto/des/fcrypt.o crypto/des/xcbc_enc.o crypto/des/rpc_enc.o  crypto/des/cbc_cksm.o \
	crypto/des/ede_cbcm_enc.o crypto/des/des_old.o crypto/des/des_old2.o crypto/des/read2pwd.o

SRC_crypto_des= $(LIBSRC_crypto_des)

EXHEADER_crypto_des= crypto/des/des.h crypto/des/des_old.h
HEADER_crypto_des=	crypto/des/des_locl.h crypto/des/rpc_des.h crypto/des/spr.h crypto/des/des_ver.h $(EXHEADER_crypto_des)

ALL_crypto_des=    $(GENERAL_crypto_des) $(SRC_crypto_des) $(HEADER_crypto_des)


all: all_crypto_des
all_crypto_des:	crypto/des/lib

crypto/des/lib:	$(LIBOBJ_crypto_des)
	$(ARX) $(LIB_crypto_des) $(LIBOBJ_crypto_des)
	$(RANLIB) $(LIB_crypto_des) || echo Never mind.
	@touch crypto/des/lib

crypto/des/des: crypto/des/des.o crypto/des/cbc3_enc.o crypto/des/lib
	$(CC) $(CFLAGS_crypto_des) -o crypto/des/des crypto/des/des.o crypto/des/cbc3_enc.o $(LIB_crypto_des)

crypto/des/des_enc-sparc.S:	crypto/des/asm/des_enc.m4
	m4 -B 8192 crypto/des/asm/des_enc.m4 > crypto/des/des_enc-sparc.S
crypto/des/dest4-sparcv9.s:	crypto/des/asm/dest4-sparcv9.pl
	$(PERL) crypto/des/asm/dest4-sparcv9.pl $(CFLAGS_crypto_des) > $@

crypto/des/des-586.s:	crypto/des/asm/des-586.pl crypto/perlasm/x86asm.pl crypto/perlasm/cbc.pl
	$(PERL) crypto/des/asm/des-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_des) > $@
crypto/des/crypt586.s:	crypto/des/asm/crypt586.pl crypto/perlasm/x86asm.pl crypto/perlasm/cbc.pl
	$(PERL) crypto/des/asm/crypt586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_des) > $@

files: files_crypto_des
files_crypto_des:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_des
links_crypto_des:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_des)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_des)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_des)

# We need to use force because 'install' matches 'INSTALL' on case
# insensitive systems
FRC.install: FRC.install_crypto_des
FRC.install_crypto_des:
install: install_crypto_des
install_crypto_des: FRC.install_crypto_des
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_des)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_des
tags_crypto_des:
	ctags $(SRC_crypto_des)

tests: tests_crypto_des
tests_crypto_des:

lint: lint_crypto_des
lint_crypto_des:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_des)>crypto/des/fluff

dclean: dclean_crypto_des
dclean_crypto_des:

clean: clean_crypto_des
clean_crypto_des:
	rm -f crypto/des/*.s crypto/des/*.o crypto/des/*.d crypto/des/*.obj crypto/des/des crypto/des/lib crypto/des/tags crypto/des/core crypto/des/.pure crypto/des/.nfs* crypto/des/*.old crypto/des/*.bak crypto/des/fluff

