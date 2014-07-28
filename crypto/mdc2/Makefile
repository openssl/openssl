#
# OpenSSL/crypto/mdc2/Makefile
#

DIR_crypto_mdc2=	mdc2
INCLUDES_crypto_mdc2=

CFLAGS_crypto_mdc2= $(INCLUDES_crypto_mdc2) $(CFLAG)

GENERAL_crypto_mdc2=Makefile
TEST_crypto_mdc2= mdc2test.c
APPS_crypto_mdc2=

LIB_crypto_mdc2=$(TOP_crypto_mdc2)/libcrypto.a
LIBSRC_crypto_mdc2=mdc2dgst.c mdc2_one.c
LIBOBJ_crypto_mdc2=mdc2dgst.o mdc2_one.o

SRC_crypto_mdc2= $(LIBSRC_crypto_mdc2)

EXHEADER_crypto_mdc2= mdc2.h
HEADER_crypto_mdc2=	$(EXHEADER_crypto_mdc2)

ALL_crypto_mdc2=    $(GENERAL_crypto_mdc2) $(SRC_crypto_mdc2) $(HEADER_crypto_mdc2)

top: top_crypto_mdc2
top_crypto_mdc2:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_mdc2) sub_all)

all: all_crypto_mdc2
all_crypto_mdc2:	lib

lib:	$(LIBOBJ_crypto_mdc2)
	$(ARX) $(LIB_crypto_mdc2) $(LIBOBJ_crypto_mdc2)
	$(RANLIB) $(LIB_crypto_mdc2) || echo Never mind.
	@touch lib

files: files_crypto_mdc2
files_crypto_mdc2:
	$(PERL) $(TOP_crypto_mdc2)/util/files.pl TOP=$(TOP_crypto_mdc2) Makefile >> $(TOP_crypto_mdc2)/MINFO

links: links_crypto_mdc2
links_crypto_mdc2:
	@$(PERL) $(TOP_crypto_mdc2)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_mdc2)
	@$(PERL) $(TOP_crypto_mdc2)/util/mklink.pl ../../test $(TEST_crypto_mdc2)
	@$(PERL) $(TOP_crypto_mdc2)/util/mklink.pl ../../apps $(APPS_crypto_mdc2)

install: install_crypto_mdc2
install_crypto_mdc2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_mdc2)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_mdc2
tags_crypto_mdc2:
	ctags $(SRC_crypto_mdc2)

tests: tests_crypto_mdc2
tests_crypto_mdc2:

lint: lint_crypto_mdc2
lint_crypto_mdc2:
	lint -DLINT $(INCLUDES_crypto_mdc2) $(SRC_crypto_mdc2)>fluff

dclean: dclean_crypto_mdc2
dclean_crypto_mdc2:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_mdc2
clean_crypto_mdc2:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_mdc2) $(CPPFLAGS) -c -o $@ $<
