#
# OpenSSL/crypto/md4/Makefile
#

CPP_crypto_md4=    $(CC) -E
INCLUDES_crypto_md4=

CFLAGS_crypto_md4= $(INCLUDES_crypto_md4) $(CFLAG)

GENERAL_crypto_md4=Makefile
TEST_crypto_md4=md4test.c
APPS_crypto_md4=md4.c

LIB_crypto_md4=$(TOP_crypto_md4)/libcrypto.a
LIBSRC_crypto_md4=md4_dgst.c md4_one.c
LIBOBJ_crypto_md4=md4_dgst.o md4_one.o

SRC_crypto_md4= $(LIBSRC_crypto_md4)

EXHEADER_crypto_md4= md4.h
HEADER_crypto_md4= md4_locl.h $(EXHEADER_crypto_md4)

ALL_crypto_md4=    $(GENERAL_crypto_md4) $(SRC_crypto_md4) $(HEADER_crypto_md4)


all: all_crypto_md4
all_crypto_md4:    lib

lib:    $(LIBOBJ_crypto_md4)
	$(ARX) $(LIB_crypto_md4) $(LIBOBJ_crypto_md4)
	$(RANLIB) $(LIB_crypto_md4) || echo Never mind.
	@touch lib

files: files_crypto_md4
files_crypto_md4:
	$(PERL) $(TOP_crypto_md4)/util/files.pl TOP=$(TOP_crypto_md4) Makefile >> $(TOP_crypto_md4)/MINFO

links: links_crypto_md4
links_crypto_md4:
	@$(PERL) $(TOP_crypto_md4)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_md4)
	@$(PERL) $(TOP_crypto_md4)/util/mklink.pl ../../test $(TEST_crypto_md4)
	@$(PERL) $(TOP_crypto_md4)/util/mklink.pl ../../apps $(APPS_crypto_md4)

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
	lint -DLINT $(INCLUDES_crypto_md4) $(SRC_crypto_md4)>fluff

dclean: dclean_crypto_md4
dclean_crypto_md4:
	rm -f ../../include/openssl/$(EXHEADER_crypto_md4) ../../test/$(TEST_crypto_md4) ../../apps/$(APPS_crypto_md4)

clean: clean_crypto_md4
clean_crypto_md4:
	rm -f asm/mx86unix.cpp *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_md4) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_md4) $(CPPFLAGS) -c -o $@ $<
