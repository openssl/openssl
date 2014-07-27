#
# OpenSSL/crypto/lhash/Makefile
#

INCLUDES_crypto_lhash=

CFLAGS_crypto_lhash= $(INCLUDES_crypto_lhash) $(CFLAG)

GENERAL_crypto_lhash=Makefile
TEST_crypto_lhash=
APPS_crypto_lhash=

LIB_crypto_lhash=$(TOP_crypto_lhash)/libcrypto.a
LIBSRC_crypto_lhash=lhash.c lh_stats.c
LIBOBJ_crypto_lhash=lhash.o lh_stats.o

SRC_crypto_lhash= $(LIBSRC_crypto_lhash)

EXHEADER_crypto_lhash= lhash.h
HEADER_crypto_lhash=	$(EXHEADER_crypto_lhash)

ALL_crypto_lhash=    $(GENERAL_crypto_lhash) $(SRC_crypto_lhash) $(HEADER_crypto_lhash)


all: all_crypto_lhash
all_crypto_lhash:	lib

lib:	$(LIBOBJ_crypto_lhash)
	$(ARX) $(LIB_crypto_lhash) $(LIBOBJ_crypto_lhash)
	$(RANLIB) $(LIB_crypto_lhash) || echo Never mind.
	@touch lib

files: files_crypto_lhash
files_crypto_lhash:
	$(PERL) $(TOP_crypto_lhash)/util/files.pl TOP=$(TOP_crypto_lhash) Makefile >> $(TOP_crypto_lhash)/MINFO

links: links_crypto_lhash
links_crypto_lhash:
	@$(PERL) $(TOP_crypto_lhash)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_lhash)
	@$(PERL) $(TOP_crypto_lhash)/util/mklink.pl ../../test $(TEST_crypto_lhash)
	@$(PERL) $(TOP_crypto_lhash)/util/mklink.pl ../../apps $(APPS_crypto_lhash)

install: install_crypto_lhash
install_crypto_lhash:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_lhash)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_lhash
tags_crypto_lhash:
	ctags $(SRC_crypto_lhash)

tests: tests_crypto_lhash
tests_crypto_lhash:

lint: lint_crypto_lhash
lint_crypto_lhash:
	lint -DLINT $(INCLUDES_crypto_lhash) $(SRC_crypto_lhash)>fluff

dclean: dclean_crypto_lhash
dclean_crypto_lhash:

clean: clean_crypto_lhash
clean_crypto_lhash:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_lhash) $(CPPFLAGS) -c -o $@ $<
