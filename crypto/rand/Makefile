#
# OpenSSL/crypto/rand/Makefile
#


CFLAGS_crypto_rand= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_rand=crypto/rand/Makefile
TEST_crypto_rand= crypto/rand/randtest.c
APPS_crypto_rand=

LIB_crypto_rand=libcrypto.a
LIBSRC_crypto_rand=crypto/rand/md_rand.c crypto/rand/randfile.c crypto/rand/rand_lib.c crypto/rand/rand_err.c crypto/rand/rand_egd.c \
	crypto/rand/rand_win.c crypto/rand/rand_unix.c crypto/rand/rand_os2.c crypto/rand/rand_nw.c
LIBOBJ_crypto_rand=crypto/rand/md_rand.o crypto/rand/randfile.o crypto/rand/rand_lib.o crypto/rand/rand_err.o crypto/rand/rand_egd.o \
	crypto/rand/rand_win.o crypto/rand/rand_unix.o crypto/rand/rand_os2.o crypto/rand/rand_nw.o

SRC_crypto_rand= $(LIBSRC_crypto_rand)

EXHEADER_crypto_rand= crypto/rand/rand.h
HEADER_crypto_rand=	$(EXHEADER_crypto_rand)

ALL_crypto_rand=    $(GENERAL_crypto_rand) $(SRC_crypto_rand) $(HEADER_crypto_rand)


all: all_crypto_rand
all_crypto_rand:	crypto/rand/lib

crypto/rand/lib:	$(LIBOBJ_crypto_rand)
	$(ARX) $(LIB_crypto_rand) $(LIBOBJ_crypto_rand)
	$(RANLIB) $(LIB_crypto_rand) || echo Never mind.
	@touch crypto/rand/lib

files: files_crypto_rand
files_crypto_rand:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_rand
links_crypto_rand:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_rand)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_rand)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_rand)

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
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_rand)>crypto/rand/fluff

dclean: dclean_crypto_rand
dclean_crypto_rand:

clean: clean_crypto_rand
clean_crypto_rand:
	rm -f crypto/rand/*.o crypto/rand/*.d crypto/rand/*.obj crypto/rand/lib crypto/rand/tags crypto/rand/core crypto/rand/.pure crypto/rand/.nfs* crypto/rand/*.old crypto/rand/*.bak crypto/rand/fluff

