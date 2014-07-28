#
# OpenSSL/crypto/des/Makefile
#

DIR_crypto_des=	des
CPP_crypto_des=	$(CC) -E
INCLUDES_crypto_des=-I$(TOP_crypto_des) -I../../include

CFLAGS_crypto_des= $(INCLUDES_crypto_des) $(CFLAG)
ASFLAGS_crypto_des= $(INCLUDES_crypto_des) $(ASFLAG)
AFLAGS_crypto_des= $(ASFLAGS_crypto_des)

GENERAL_crypto_des=Makefile
TEST_crypto_des=destest.c
APPS_crypto_des=

LIB_crypto_des=$(TOP_crypto_des)/libcrypto.a
LIBSRC_crypto_des=	cbc_cksm.c cbc_enc.c  cfb64enc.c cfb_enc.c  \
	ecb3_enc.c ecb_enc.c  enc_read.c enc_writ.c \
	fcrypt.c ofb64enc.c ofb_enc.c  pcbc_enc.c \
	qud_cksm.c rand_key.c rpc_enc.c  set_key.c  \
	des_enc.c fcrypt_b.c \
	xcbc_enc.c \
	str2key.c  cfb64ede.c ofb64ede.c ede_cbcm_enc.c des_old.c des_old2.c \
	read2pwd.c

LIBOBJ_crypto_des= set_key.o  ecb_enc.o  cbc_enc.o \
	ecb3_enc.o cfb64enc.o cfb64ede.o cfb_enc.o  ofb64ede.o \
	enc_read.o enc_writ.o ofb64enc.o \
	ofb_enc.o  str2key.o  pcbc_enc.o qud_cksm.o rand_key.o \
	${DES_ENC} \
	fcrypt.o xcbc_enc.o rpc_enc.o  cbc_cksm.o \
	ede_cbcm_enc.o des_old.o des_old2.o read2pwd.o

SRC_crypto_des= $(LIBSRC_crypto_des)

EXHEADER_crypto_des= des.h des_old.h
HEADER_crypto_des=	des_locl.h rpc_des.h spr.h des_ver.h $(EXHEADER_crypto_des)

ALL_crypto_des=    $(GENERAL_crypto_des) $(SRC_crypto_des) $(HEADER_crypto_des)

top: top_crypto_des
top_crypto_des:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_des) sub_all)

all: all_crypto_des
all_crypto_des:	lib

lib:	$(LIBOBJ_crypto_des)
	$(ARX) $(LIB_crypto_des) $(LIBOBJ_crypto_des)
	$(RANLIB) $(LIB_crypto_des) || echo Never mind.
	@touch lib

des: des.o cbc3_enc.o lib
	$(CC) $(CFLAGS_crypto_des) -o des des.o cbc3_enc.o $(LIB_crypto_des)

des_enc-sparc.S:	asm/des_enc.m4
	m4 -B 8192 asm/des_enc.m4 > des_enc-sparc.S
dest4-sparcv9.s:	asm/dest4-sparcv9.pl
	$(PERL) asm/dest4-sparcv9.pl $(CFLAGS_crypto_des) > $@

des-586.s:	asm/des-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/des-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_des) > $@
crypt586.s:	asm/crypt586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/crypt586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_des) > $@

files: files_crypto_des
files_crypto_des:
	$(PERL) $(TOP_crypto_des)/util/files.pl TOP=$(TOP_crypto_des) Makefile >> $(TOP_crypto_des)/MINFO

links: links_crypto_des
links_crypto_des:
	@$(PERL) $(TOP_crypto_des)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_des)
	@$(PERL) $(TOP_crypto_des)/util/mklink.pl ../../test $(TEST_crypto_des)
	@$(PERL) $(TOP_crypto_des)/util/mklink.pl ../../apps $(APPS_crypto_des)

# We need to use force because 'install' matches 'INSTALL' on case
# insensitive systems
FRC.install: FRC.install_crypto_des
FRC.install_crypto_des:
install: install_crypto_des
install_crypto_des: FRC.install
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
	lint -DLINT $(INCLUDES_crypto_des) $(SRC_crypto_des)>fluff

dclean: dclean_crypto_des
dclean_crypto_des:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_des
clean_crypto_des:
	rm -f *.s *.o *.d *.obj des lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_des) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_des) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_des) -o $@ $<
