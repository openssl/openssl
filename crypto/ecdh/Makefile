#
# crypto/ecdh/Makefile
#

INCLUDES_crypto_ecdh= -I.. -I$(TOP_crypto_ecdh) -I../../include

CFLAGS_crypto_ecdh= $(INCLUDES_crypto_ecdh) $(CFLAG)

GENERAL_crypto_ecdh=Makefile
TEST_crypto_ecdh=ecdhtest.c
APPS_crypto_ecdh=

LIB_crypto_ecdh=$(TOP_crypto_ecdh)/libcrypto.a
LIBSRC_crypto_ecdh=	ech_lib.c ech_ossl.c ech_key.c ech_err.c ech_kdf.c

LIBOBJ_crypto_ecdh=	ech_lib.o ech_ossl.o ech_key.o ech_err.o ech_kdf.o

SRC_crypto_ecdh= $(LIBSRC_crypto_ecdh)

EXHEADER_crypto_ecdh= ecdh.h
HEADER_crypto_ecdh=	ech_locl.h $(EXHEADER_crypto_ecdh)

ALL_crypto_ecdh=    $(GENERAL_crypto_ecdh) $(SRC_crypto_ecdh) $(HEADER_crypto_ecdh)


all: all_crypto_ecdh
all_crypto_ecdh:	lib

lib:	$(LIBOBJ_crypto_ecdh)
	$(ARX) $(LIB_crypto_ecdh) $(LIBOBJ_crypto_ecdh)
	$(RANLIB) $(LIB_crypto_ecdh) || echo Never mind.
	@touch lib

files: files_crypto_ecdh
files_crypto_ecdh:
	$(PERL) $(TOP_crypto_ecdh)/util/files.pl TOP=$(TOP_crypto_ecdh) Makefile >> $(TOP_crypto_ecdh)/MINFO

links: links_crypto_ecdh
links_crypto_ecdh:
	@$(PERL) $(TOP_crypto_ecdh)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ecdh)
	@$(PERL) $(TOP_crypto_ecdh)/util/mklink.pl ../../test $(TEST_crypto_ecdh)
	@$(PERL) $(TOP_crypto_ecdh)/util/mklink.pl ../../apps $(APPS_crypto_ecdh)

install: install_crypto_ecdh
install_crypto_ecdh:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ecdh)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ecdh
tags_crypto_ecdh:
	ctags $(SRC_crypto_ecdh)

tests: tests_crypto_ecdh
tests_crypto_ecdh:

lint: lint_crypto_ecdh
lint_crypto_ecdh:
	lint -DLINT $(INCLUDES_crypto_ecdh) $(SRC_crypto_ecdh)>fluff

dclean: dclean_crypto_ecdh
dclean_crypto_ecdh:

clean: clean_crypto_ecdh
clean_crypto_ecdh:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_ecdh) $(CPPFLAGS) -c -o $@ $<
