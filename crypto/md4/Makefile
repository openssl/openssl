#
# OpenSSL/crypto/md4/Makefile
#

CPP_crypto_md4=    $(CC) -E
INCLUDES_crypto_md4=

CFLAGS_crypto_md4= $(INCLUDES_crypto_md4) $(CFLAG)

GENERAL_crypto_md4=crypto/md4/Makefile
TEST_crypto_md4=crypto/md4/md4test.c
APPS_crypto_md4=crypto/md4/md4.c

LIB_crypto_md4=libcrypto.a
LIBSRC_crypto_md4=crypto/md4/md4_dgst.c crypto/md4/md4_one.c
LIBOBJ_crypto_md4=crypto/md4/md4_dgst.o crypto/md4/md4_one.o

SRC_crypto_md4= $(LIBSRC_crypto_md4)

EXHEADER_crypto_md4= crypto/md4/md4.h
HEADER_crypto_md4= crypto/md4/md4_locl.h $(EXHEADER_crypto_md4)

ALL_crypto_md4=    $(GENERAL_crypto_md4) $(SRC_crypto_md4) $(HEADER_crypto_md4)


all: all_crypto_md4
all_crypto_md4:    crypto/md4/lib

crypto/md4/lib:    $(LIBOBJ_crypto_md4)
	$(ARX) $(LIB_crypto_md4) $(LIBOBJ_crypto_md4)
	$(RANLIB) $(LIB_crypto_md4) || echo Never mind.
	@touch crypto/md4/lib

files: files_crypto_md4
files_crypto_md4:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_md4
links_crypto_md4:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_md4)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_md4)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_md4)

install: install_crypto_md4
install_crypto_md4:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_md4)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_md4
tags_crypto_md4:
	ctags $(SRC_crypto_md4)

tests: tests_crypto_md4
tests_crypto_md4:

lint: lint_crypto_md4
lint_crypto_md4:
	lint -DLINT $(INCLUDES_crypto_md4) $(SRC_crypto_md4)>crypto/md4/fluff

dclean: dclean_crypto_md4
dclean_crypto_md4:
	rm -f $(EXHEADER_crypto_md4) $(TEST_crypto_md4) $(APPS_crypto_md4)

clean: clean_crypto_md4
clean_crypto_md4:
	rm -f asm/mx86unix.cpp crypto/md4/*.o crypto/md4/*.d asm/*.o crypto/md4/*.obj crypto/md4/lib crypto/md4/tags crypto/md4/core crypto/md4/.pure crypto/md4/.nfs* crypto/md4/*.old crypto/md4/*.bak crypto/md4/fluff

.S.s:
	$(CPP_crypto_md4) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_md4) $(CPPFLAGS) -c -o $@ $<
