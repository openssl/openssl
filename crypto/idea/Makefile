#
# OpenSSL/crypto/idea/Makefile
#

DIR_crypto_idea=	idea
INCLUDES_crypto_idea=

CFLAGS_crypto_idea= $(INCLUDES_crypto_idea) $(CFLAG)

GENERAL_crypto_idea=Makefile
TEST_crypto_idea=ideatest.c
APPS_crypto_idea=

LIB_crypto_idea=$(TOP_crypto_idea)/libcrypto.a
LIBSRC_crypto_idea=i_cbc.c i_cfb64.c i_ofb64.c i_ecb.c i_skey.c
LIBOBJ_crypto_idea=i_cbc.o i_cfb64.o i_ofb64.o i_ecb.o i_skey.o

SRC_crypto_idea= $(LIBSRC_crypto_idea)

EXHEADER_crypto_idea= idea.h
HEADER_crypto_idea=	idea_lcl.h $(EXHEADER_crypto_idea)

ALL_crypto_idea=    $(GENERAL_crypto_idea) $(SRC_crypto_idea) $(HEADER_crypto_idea)

top: top_crypto_idea
top_crypto_idea:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_idea) sub_all)

all: all_crypto_idea
all_crypto_idea:	lib

lib: lib_crypto_idea
lib_crypto_idea:	$(LIBOBJ_crypto_idea)
	$(ARX) $(LIB_crypto_idea) $(LIBOBJ_crypto_idea)
	$(RANLIB) $(LIB_crypto_idea) || echo Never mind.
	@touch lib

files: files_crypto_idea
files_crypto_idea:
	$(PERL) $(TOP_crypto_idea)/util/files.pl TOP=$(TOP_crypto_idea) Makefile >> $(TOP_crypto_idea)/MINFO

links: links_crypto_idea
links_crypto_idea:
	@$(PERL) $(TOP_crypto_idea)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_idea)
	@$(PERL) $(TOP_crypto_idea)/util/mklink.pl ../../test $(TEST_crypto_idea)
	@$(PERL) $(TOP_crypto_idea)/util/mklink.pl ../../apps $(APPS_crypto_idea)

install: install_crypto_idea
install_crypto_idea:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_idea)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_idea
tags_crypto_idea:
	ctags $(SRC_crypto_idea)

tests: tests_crypto_idea
tests_crypto_idea:

lint: lint_crypto_idea
lint_crypto_idea:
	lint -DLINT $(INCLUDES_crypto_idea) $(SRC_crypto_idea)>fluff

dclean: dclean_crypto_idea
dclean_crypto_idea:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_idea
clean_crypto_idea:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_idea) $(CPPFLAGS) -c -o $@ $<
