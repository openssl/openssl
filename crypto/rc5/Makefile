#
# OpenSSL/crypto/rc5/Makefile
#

CPP_crypto_rc5=	$(CC) -E


CFLAGS_crypto_rc5= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_rc5= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_rc5= $(ASFLAGS_crypto_rc5)

GENERAL_crypto_rc5=crypto/rc5/Makefile
TEST_crypto_rc5=crypto/rc5/rc5test.c
APPS_crypto_rc5=

LIB_crypto_rc5=libcrypto.a
LIBSRC_crypto_rc5=crypto/rc5/rc5_skey.c crypto/rc5/rc5_ecb.c crypto/rc5/rc5_enc.c crypto/rc5/rc5cfb64.c crypto/rc5/rc5ofb64.c 
LIBOBJ_crypto_rc5=crypto/rc5/rc5_skey.o crypto/rc5/rc5_ecb.o $(RC5_ENC) crypto/rc5/rc5cfb64.o crypto/rc5/rc5ofb64.o

SRC_crypto_rc5= $(LIBSRC_crypto_rc5)

EXHEADER_crypto_rc5= crypto/rc5/rc5.h
HEADER_crypto_rc5=	crypto/rc5/rc5_locl.h $(EXHEADER_crypto_rc5)

ALL_crypto_rc5=    $(GENERAL_crypto_rc5) $(SRC_crypto_rc5) $(HEADER_crypto_rc5)


all: all_crypto_rc5
all_crypto_rc5:	crypto/rc5/lib

crypto/rc5/lib:	$(LIBOBJ_crypto_rc5)
	$(ARX) $(LIB_crypto_rc5) $(LIBOBJ_crypto_rc5)
	$(RANLIB) $(LIB_crypto_rc5) || echo Never mind.
	@touch crypto/rc5/lib

crypto/rc5/rc5-586.s: crypto/rc5/asm/rc5-586.pl crypto/perlasm/x86asm.pl crypto/perlasm/cbc.pl
	$(PERL) crypto/rc5/asm/rc5-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_rc5) > $@

files: files_crypto_rc5
files_crypto_rc5:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_rc5
links_crypto_rc5:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_rc5)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_rc5)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_rc5)

install: install_crypto_rc5
install_crypto_rc5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rc5)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc5
tags_crypto_rc5:
	ctags $(SRC_crypto_rc5)

tests: tests_crypto_rc5
tests_crypto_rc5:

lint: lint_crypto_rc5
lint_crypto_rc5:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_rc5)>crypto/rc5/fluff

dclean: dclean_crypto_rc5
dclean_crypto_rc5:

clean: clean_crypto_rc5
clean_crypto_rc5:
	rm -f crypto/rc5/*.s crypto/rc5/*.o crypto/rc5/*.d crypto/rc5/*.obj crypto/rc5/lib crypto/rc5/tags crypto/rc5/core crypto/rc5/.pure crypto/rc5/.nfs* crypto/rc5/*.old crypto/rc5/*.bak crypto/rc5/fluff

