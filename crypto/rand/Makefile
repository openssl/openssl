#
# OpenSSL/crypto/rand/Makefile
#

DIR_crypto_rand=	rand
INCLUDES_crypto_rand=

CFLAGS_crypto_rand= $(INCLUDES_crypto_rand) $(CFLAG)

GENERAL_crypto_rand=Makefile
TEST_crypto_rand= randtest.c
APPS_crypto_rand=

LIB_crypto_rand=$(TOP_crypto_rand)/libcrypto.a
LIBSRC_crypto_rand=md_rand.c randfile.c rand_lib.c rand_err.c rand_egd.c \
	rand_win.c rand_unix.c rand_os2.c rand_nw.c
LIBOBJ_crypto_rand=md_rand.o randfile.o rand_lib.o rand_err.o rand_egd.o \
	rand_win.o rand_unix.o rand_os2.o rand_nw.o

SRC_crypto_rand= $(LIBSRC_crypto_rand)

EXHEADER_crypto_rand= rand.h
HEADER_crypto_rand=	$(EXHEADER_crypto_rand)

ALL_crypto_rand=    $(GENERAL_crypto_rand) $(SRC_crypto_rand) $(HEADER_crypto_rand)

top: top_crypto_rand
top_crypto_rand:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_rand) sub_all)

all: all_crypto_rand
all_crypto_rand:	lib

lib:	$(LIBOBJ_crypto_rand)
	$(ARX) $(LIB_crypto_rand) $(LIBOBJ_crypto_rand)
	$(RANLIB) $(LIB_crypto_rand) || echo Never mind.
	@touch lib

files: files_crypto_rand
files_crypto_rand:
	$(PERL) $(TOP_crypto_rand)/util/files.pl TOP=$(TOP_crypto_rand) Makefile >> $(TOP_crypto_rand)/MINFO

links: links_crypto_rand
links_crypto_rand:
	@$(PERL) $(TOP_crypto_rand)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_rand)
	@$(PERL) $(TOP_crypto_rand)/util/mklink.pl ../../test $(TEST_crypto_rand)
	@$(PERL) $(TOP_crypto_rand)/util/mklink.pl ../../apps $(APPS_crypto_rand)

install: install_crypto_rand
install_crypto_rand:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rand)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rand
tags_crypto_rand:
	ctags $(SRC_crypto_rand)

tests: tests_crypto_rand
tests_crypto_rand:

lint: lint_crypto_rand
lint_crypto_rand:
	lint -DLINT $(INCLUDES_crypto_rand) $(SRC_crypto_rand)>fluff

dclean: dclean_crypto_rand
dclean_crypto_rand:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_rand
clean_crypto_rand:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_rand) $(CPPFLAGS) -c -o $@ $<
