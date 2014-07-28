#
# OpenSSL/crypto/rc2/Makefile
#

DIR_crypto_rc2=	rc2
INCLUDES_crypto_rc2=

CFLAGS_crypto_rc2= $(INCLUDES_crypto_rc2) $(CFLAG)

GENERAL_crypto_rc2=Makefile
TEST_crypto_rc2=rc2test.c
APPS_crypto_rc2=

LIB_crypto_rc2=$(TOP_crypto_rc2)/libcrypto.a
LIBSRC_crypto_rc2=rc2_ecb.c rc2_skey.c rc2_cbc.c rc2cfb64.c rc2ofb64.c
LIBOBJ_crypto_rc2=rc2_ecb.o rc2_skey.o rc2_cbc.o rc2cfb64.o rc2ofb64.o

SRC_crypto_rc2= $(LIBSRC_crypto_rc2)

EXHEADER_crypto_rc2= rc2.h
HEADER_crypto_rc2=	rc2_locl.h $(EXHEADER_crypto_rc2)

ALL_crypto_rc2=    $(GENERAL_crypto_rc2) $(SRC_crypto_rc2) $(HEADER_crypto_rc2)

top: top_crypto_rc2
top_crypto_rc2:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_rc2) sub_all)

all: all_crypto_rc2
all_crypto_rc2:	lib

lib:	$(LIBOBJ_crypto_rc2)
	$(ARX) $(LIB_crypto_rc2) $(LIBOBJ_crypto_rc2)
	$(RANLIB) $(LIB_crypto_rc2) || echo Never mind.
	@touch lib

files: files_crypto_rc2
files_crypto_rc2:
	$(PERL) $(TOP_crypto_rc2)/util/files.pl TOP=$(TOP_crypto_rc2) Makefile >> $(TOP_crypto_rc2)/MINFO

links: links_crypto_rc2
links_crypto_rc2:
	@$(PERL) $(TOP_crypto_rc2)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_rc2)
	@$(PERL) $(TOP_crypto_rc2)/util/mklink.pl ../../test $(TEST_crypto_rc2)
	@$(PERL) $(TOP_crypto_rc2)/util/mklink.pl ../../apps $(APPS_crypto_rc2)

install: install_crypto_rc2
install_crypto_rc2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rc2)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc2
tags_crypto_rc2:
	ctags $(SRC_crypto_rc2)

tests: tests_crypto_rc2
tests_crypto_rc2:

lint: lint_crypto_rc2
lint_crypto_rc2:
	lint -DLINT $(INCLUDES_crypto_rc2) $(SRC_crypto_rc2)>fluff

dclean: dclean_crypto_rc2
dclean_crypto_rc2:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_rc2
clean_crypto_rc2:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_rc2) $(CPPFLAGS) -c -o $@ $<
