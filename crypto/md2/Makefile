#
# OpenSSL/crypto/md/Makefile
#

INCLUDES_crypto_md2=

CFLAGS_crypto_md2= $(INCLUDES_crypto_md2) $(CFLAG)

GENERAL_crypto_md2=Makefile
TEST_crypto_md2=md2test.c
APPS_crypto_md2=

LIB_crypto_md2=$(TOP_crypto_md2)/libcrypto.a
LIBSRC_crypto_md2=md2_dgst.c md2_one.c
LIBOBJ_crypto_md2=md2_dgst.o md2_one.o

SRC_crypto_md2= $(LIBSRC_crypto_md2)

EXHEADER_crypto_md2= md2.h
HEADER_crypto_md2=	$(EXHEADER_crypto_md2)

ALL_crypto_md2=    $(GENERAL_crypto_md2) $(SRC_crypto_md2) $(HEADER_crypto_md2)


all: all_crypto_md2
all_crypto_md2:	lib

lib:	$(LIBOBJ_crypto_md2)
	$(ARX) $(LIB_crypto_md2) $(LIBOBJ_crypto_md2)
	$(RANLIB) $(LIB_crypto_md2) || echo Never mind.
	@touch lib

files: files_crypto_md2
files_crypto_md2:
	$(PERL) $(TOP_crypto_md2)/util/files.pl TOP=$(TOP_crypto_md2) Makefile >> $(TOP_crypto_md2)/MINFO

links: links_crypto_md2
links_crypto_md2:
	@$(PERL) $(TOP_crypto_md2)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_md2)
	@$(PERL) $(TOP_crypto_md2)/util/mklink.pl ../../test $(TEST_crypto_md2)
	@$(PERL) $(TOP_crypto_md2)/util/mklink.pl ../../apps $(APPS_crypto_md2)

install: install_crypto_md2
install_crypto_md2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_md2)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_md2
tags_crypto_md2:
	ctags $(SRC_crypto_md2)

tests: tests_crypto_md2
tests_crypto_md2:

lint: lint_crypto_md2
lint_crypto_md2:
	lint -DLINT $(INCLUDES_crypto_md2) $(SRC_crypto_md2)>fluff

dclean: dclean_crypto_md2
dclean_crypto_md2:

clean: clean_crypto_md2
clean_crypto_md2:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_md2) $(CPPFLAGS) -c -o $@ $<
