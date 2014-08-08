#
# OpenSSL/crypto/cms/Makefile
#


CFLAGS_crypto_cms= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_cms=crypto/cms/Makefile
TEST_crypto_cms=
APPS_crypto_cms=

LIB_crypto_cms=libcrypto.a
LIBSRC_crypto_cms= crypto/cms/cms_lib.c crypto/cms/cms_asn1.c crypto/cms/cms_att.c crypto/cms/cms_io.c crypto/cms/cms_smime.c crypto/cms/cms_err.c \
	crypto/cms/cms_sd.c crypto/cms/cms_dd.c crypto/cms/cms_cd.c crypto/cms/cms_env.c crypto/cms/cms_enc.c crypto/cms/cms_ess.c \
	crypto/cms/cms_pwri.c crypto/cms/cms_kari.c
LIBOBJ_crypto_cms= crypto/cms/cms_lib.o crypto/cms/cms_asn1.o crypto/cms/cms_att.o crypto/cms/cms_io.o crypto/cms/cms_smime.o crypto/cms/cms_err.o \
	crypto/cms/cms_sd.o crypto/cms/cms_dd.o crypto/cms/cms_cd.o crypto/cms/cms_env.o crypto/cms/cms_enc.o crypto/cms/cms_ess.o \
	crypto/cms/cms_pwri.o crypto/cms/cms_kari.o

SRC_crypto_cms= $(LIBSRC_crypto_cms)

EXHEADER_crypto_cms=  crypto/cms/cms.h
HEADER_crypto_cms=	crypto/cms/cms_lcl.h $(EXHEADER_crypto_cms)

ALL_crypto_cms=    $(GENERAL_crypto_cms) $(SRC_crypto_cms) $(HEADER_crypto_cms)

all: all_crypto_cms
all_crypto_cms:	crypto/cms/lib

crypto/cms/lib:	$(LIBOBJ_crypto_cms)
	$(ARX) $(LIB_crypto_cms) $(LIBOBJ_crypto_cms)
	$(RANLIB) $(LIB_crypto_cms) || echo Never mind.
	@touch crypto/cms/lib

files: files_crypto_cms
files_crypto_cms:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_cms
links_crypto_cms:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_cms)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_cms)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_cms)

install: install_crypto_cms
install_crypto_cms:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_cms)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cms
tags_crypto_cms:
	ctags $(SRC_crypto_cms)

tests: tests_crypto_cms
tests_crypto_cms:

lint: lint_crypto_cms
lint_crypto_cms:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_cms)>crypto/cms/fluff

dclean: dclean_crypto_cms
dclean_crypto_cms:

clean: clean_crypto_cms
clean_crypto_cms:
	rm -f crypto/cms/*.o crypto/cms/*.d crypto/cms/*.obj crypto/cms/lib crypto/cms/tags crypto/cms/core crypto/cms/.pure crypto/cms/.nfs* crypto/cms/*.old crypto/cms/*.bak crypto/cms/fluff

