#
# OpenSSL/crypto/conf/Makefile
#

INCLUDES_crypto_conf= -Icrypto -I. -Iinclude

CFLAGS_crypto_conf= $(INCLUDES_crypto_conf) $(CFLAG)

GENERAL_crypto_conf=crypto/conf/Makefile
TEST_crypto_conf=
APPS_crypto_conf=

LIB_crypto_conf=libcrypto.a
LIBSRC_crypto_conf= crypto/conf/conf_err.c crypto/conf/conf_lib.c crypto/conf/conf_api.c crypto/conf/conf_def.c crypto/conf/conf_mod.c \
	 crypto/conf/conf_mall.c crypto/conf/conf_sap.c

LIBOBJ_crypto_conf=	crypto/conf/conf_err.o crypto/conf/conf_lib.o crypto/conf/conf_api.o crypto/conf/conf_def.o crypto/conf/conf_mod.o \
	crypto/conf/conf_mall.o crypto/conf/conf_sap.o

SRC_crypto_conf= $(LIBSRC_crypto_conf)

EXHEADER_crypto_conf= crypto/conf/conf.h crypto/conf/conf_api.h
HEADER_crypto_conf=	crypto/conf/conf_def.h $(EXHEADER_crypto_conf)

ALL_crypto_conf=    $(GENERAL_crypto_conf) $(SRC_crypto_conf) $(HEADER_crypto_conf)


all: all_crypto_conf
all_crypto_conf:	crypto/conf/lib

crypto/conf/lib:	$(LIBOBJ_crypto_conf)
	$(ARX) $(LIB_crypto_conf) $(LIBOBJ_crypto_conf)
	$(RANLIB) $(LIB_crypto_conf) || echo Never mind.
	@touch crypto/conf/lib

files: files_crypto_conf
files_crypto_conf:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_conf
links_crypto_conf:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_conf)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_conf)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_conf)

install: install_crypto_conf
install_crypto_conf:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_conf)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_conf
tags_crypto_conf:
	ctags $(SRC_crypto_conf)

tests: tests_crypto_conf
tests_crypto_conf:

lint: lint_crypto_conf
lint_crypto_conf:
	lint -DLINT $(INCLUDES_crypto_conf) $(SRC_crypto_conf)>crypto/conf/fluff

dclean: dclean_crypto_conf
dclean_crypto_conf:

clean: clean_crypto_conf
clean_crypto_conf:
	rm -f crypto/conf/*.o crypto/conf/*.d crypto/conf/*.obj crypto/conf/lib crypto/conf/tags crypto/conf/core crypto/conf/.pure crypto/conf/.nfs* crypto/conf/*.old crypto/conf/*.bak crypto/conf/fluff

