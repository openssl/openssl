#
# OpenSSL/crypto/cast/Makefile
#

CPP_crypto_cast=	$(CC) -E
INCLUDES_crypto_cast=


CFLAGS_crypto_cast= $(INCLUDES_crypto_cast) $(CFLAG)
ASFLAGS_crypto_cast= $(INCLUDES_crypto_cast) $(ASFLAG)
AFLAGS_crypto_cast= $(ASFLAGS_crypto_cast)

GENERAL_crypto_cast=crypto/cast/Makefile
TEST_crypto_cast=crypto/cast/casttest.c
APPS_crypto_cast=

LIB_crypto_cast=libcrypto.a
LIBSRC_crypto_cast=crypto/cast/c_skey.c crypto/cast/c_ecb.c crypto/cast/c_enc.c crypto/cast/c_cfb64.c crypto/cast/c_ofb64.c 
LIBOBJ_crypto_cast=crypto/cast/c_skey.o crypto/cast/c_ecb.o $(CAST_ENC) crypto/cast/c_cfb64.o crypto/cast/c_ofb64.o

SRC_crypto_cast= $(LIBSRC_crypto_cast)

EXHEADER_crypto_cast= crypto/cast/cast.h
HEADER_crypto_cast=	crypto/cast/cast_s.h crypto/cast/cast_lcl.h $(EXHEADER_crypto_cast)

ALL_crypto_cast=    $(GENERAL_crypto_cast) $(SRC_crypto_cast) $(HEADER_crypto_cast)


all: all_crypto_cast
all_crypto_cast:	crypto/cast/lib

crypto/cast/lib:	$(LIBOBJ_crypto_cast)
	$(ARX) $(LIB_crypto_cast) $(LIBOBJ_crypto_cast)
	$(RANLIB) $(LIB_crypto_cast) || echo Never mind.
	@touch crypto/cast/lib

crypto/cast/cast-586.s:	crypto/cast/asm/cast-586.pl crypto/perlasm/x86asm.pl crypto/perlasm/cbc.pl
	$(PERL)	crypto/cast/asm/cast-586.pl $(PERLASM_SCHEME) $(CLAGS) $(PROCESSOR) > $@

files: files_crypto_cast
files_crypto_cast:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_cast
links_crypto_cast:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_cast)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_cast)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_cast)

install: install_crypto_cast
install_crypto_cast:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_cast)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cast
tags_crypto_cast:
	ctags $(SRC_crypto_cast)

tests: tests_crypto_cast
tests_crypto_cast:

lint: lint_crypto_cast
lint_crypto_cast:
	lint -DLINT $(INCLUDES_crypto_cast) $(SRC_crypto_cast)>crypto/cast/fluff

dclean: dclean_crypto_cast
dclean_crypto_cast:

clean: clean_crypto_cast
clean_crypto_cast:
	rm -f crypto/cast/*.s crypto/cast/*.o crypto/cast/*.d crypto/cast/*.obj crypto/cast/lib crypto/cast/tags crypto/cast/core crypto/cast/.pure crypto/cast/.nfs* crypto/cast/*.old crypto/cast/*.bak crypto/cast/fluff

.S.s:
	$(CPP_crypto_cast) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_cast) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_cast) -o $@ $<
