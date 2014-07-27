#
# OpenSSL/crypto/conf/Makefile
#

DIR_crypto_conf=	conf
INCLUDES_crypto_conf= -I.. -I$(TOP_crypto_conf) -I../../include

CFLAGS_crypto_conf= $(INCLUDES_crypto_conf) $(CFLAG)

GENERAL_crypto_conf=Makefile
TEST_crypto_conf=
APPS_crypto_conf=

LIB_crypto_conf=$(TOP_crypto_conf)/libcrypto.a
LIBSRC_crypto_conf= conf_err.c conf_lib.c conf_api.c conf_def.c conf_mod.c \
	 conf_mall.c conf_sap.c

LIBOBJ_crypto_conf=	conf_err.o conf_lib.o conf_api.o conf_def.o conf_mod.o \
	conf_mall.o conf_sap.o

SRC_crypto_conf= $(LIBSRC_crypto_conf)

EXHEADER_crypto_conf= conf.h conf_api.h
HEADER_crypto_conf=	conf_def.h $(EXHEADER_crypto_conf)

ALL_crypto_conf=    $(GENERAL_crypto_conf) $(SRC_crypto_conf) $(HEADER_crypto_conf)

top: top_crypto_conf
top_crypto_conf:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_conf) sub_all)

all: all_crypto_conf
all_crypto_conf:	lib

lib:	$(LIBOBJ_crypto_conf)
	$(ARX) $(LIB_crypto_conf) $(LIBOBJ_crypto_conf)
	$(RANLIB) $(LIB_crypto_conf) || echo Never mind.
	@touch lib

files: files_crypto_conf
files_crypto_conf:
	$(PERL) $(TOP_crypto_conf)/util/files.pl TOP=$(TOP_crypto_conf) Makefile >> $(TOP_crypto_conf)/MINFO

links: links_crypto_conf
links_crypto_conf:
	@$(PERL) $(TOP_crypto_conf)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_conf)
	@$(PERL) $(TOP_crypto_conf)/util/mklink.pl ../../test $(TEST_crypto_conf)
	@$(PERL) $(TOP_crypto_conf)/util/mklink.pl ../../apps $(APPS_crypto_conf)

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
	lint -DLINT $(INCLUDES_crypto_conf) $(SRC_crypto_conf)>fluff

dclean: dclean_crypto_conf
dclean_crypto_conf:

clean: clean_crypto_conf
clean_crypto_conf:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_conf) $(CPPFLAGS) -c -o $@ $<
