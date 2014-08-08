#
# OpenSSL/crypto/blowfish/Makefile
#

CPP_crypto_bf=	$(CC) -E
INCLUDES_crypto_bf=


CFLAGS_crypto_bf= $(INCLUDES_crypto_bf) $(CFLAG)
ASFLAGS_crypto_bf= $(INCLUDES_crypto_bf) $(ASFLAG)
AFLAGS_crypto_bf= $(ASFLAGS_crypto_bf)

GENERAL_crypto_bf=crypto/bf/Makefile
TEST_crypto_bf=crypto/bf/bftest.c
APPS_crypto_bf=

LIB_crypto_bf=libcrypto.a
LIBSRC_crypto_bf=crypto/bf/bf_skey.c crypto/bf/bf_ecb.c crypto/bf/bf_enc.c crypto/bf/bf_cfb64.c crypto/bf/bf_ofb64.c 
LIBOBJ_crypto_bf=crypto/bf/bf_skey.o crypto/bf/bf_ecb.o $(BF_ENC) crypto/bf/bf_cfb64.o crypto/bf/bf_ofb64.o

SRC_crypto_bf= $(LIBSRC_crypto_bf)

EXHEADER_crypto_bf= crypto/bf/blowfish.h
HEADER_crypto_bf=	crypto/bf/bf_pi.h crypto/bf/bf_locl.h $(EXHEADER_crypto_bf)

ALL_crypto_bf=    $(GENERAL_crypto_bf) $(SRC_crypto_bf) $(HEADER_crypto_bf)


all: all_crypto_bf
all_crypto_bf:	crypto/bf/lib

crypto/bf/lib:	$(LIBOBJ_crypto_bf)
	$(ARX) $(LIB_crypto_bf) $(LIBOBJ_crypto_bf)
	$(RANLIB) $(LIB_crypto_bf) || echo Never mind.
	@touch crypto/bf/lib

crypto/bf/bf-586.s:	crypto/bf/asm/bf-586.pl crypto/perlasm/x86asm.pl crypto/perlasm/cbc.pl
	$(PERL) crypto/bf/asm/bf-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_bf) $(PROCESSOR) > $@

files: files_crypto_bf
files_crypto_bf:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_bf
links_crypto_bf:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_bf)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_bf)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_bf)

# We need to use force because 'install' matches 'INSTALL' on case
# insensitive systems
FRC.install: FRC.install_crypto_bf
FRC.install_crypto_bf:
install: install_crypto_bf
install_crypto_bf: FRC.install_crypto_bf
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_bf)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_bf
tags_crypto_bf:
	ctags $(SRC_crypto_bf)

tests: tests_crypto_bf
tests_crypto_bf:

lint: lint_crypto_bf
lint_crypto_bf:
	lint -DLINT $(INCLUDES_crypto_bf) $(SRC_crypto_bf)>crypto/bf/fluff

dclean: dclean_crypto_bf
dclean_crypto_bf:

clean: clean_crypto_bf
clean_crypto_bf:
	rm -f crypto/bf/*.s crypto/bf/*.o crypto/bf/*.d crypto/bf/*.obj crypto/bf/lib crypto/bf/tags crypto/bf/core crypto/bf/.pure crypto/bf/.nfs* crypto/bf/*.old crypto/bf/*.bak crypto/bf/fluff

