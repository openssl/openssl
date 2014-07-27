#
# OpenSSL/crypto/cmac/Makefile
#

INCLUDES_crypto_cmac=

CFLAGS_crypto_cmac= $(INCLUDES_crypto_cmac) $(CFLAG)

GENERAL_crypto_cmac=Makefile
TEST_crypto_cmac=
APPS_crypto_cmac=

LIB_crypto_cmac=$(TOP_crypto_cmac)/libcrypto.a
LIBSRC_crypto_cmac=cmac.c cm_ameth.c cm_pmeth.c
LIBOBJ_crypto_cmac=cmac.o cm_ameth.o cm_pmeth.o

SRC_crypto_cmac= $(LIBSRC_crypto_cmac)

EXHEADER_crypto_cmac= cmac.h
HEADER_crypto_cmac=	$(EXHEADER_crypto_cmac)

ALL_crypto_cmac=    $(GENERAL_crypto_cmac) $(SRC_crypto_cmac) $(HEADER_crypto_cmac)


all: all_crypto_cmac
all_crypto_cmac:	lib

lib:	$(LIBOBJ_crypto_cmac)
	$(ARX) $(LIB_crypto_cmac) $(LIBOBJ_crypto_cmac)
	$(RANLIB) $(LIB_crypto_cmac) || echo Never mind.
	@touch lib

files: files_crypto_cmac
files_crypto_cmac:
	$(PERL) $(TOP_crypto_cmac)/util/files.pl TOP=$(TOP_crypto_cmac) Makefile >> $(TOP_crypto_cmac)/MINFO

links: links_crypto_cmac
links_crypto_cmac:
	@$(PERL) $(TOP_crypto_cmac)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_cmac)
	@$(PERL) $(TOP_crypto_cmac)/util/mklink.pl ../../test $(TEST_crypto_cmac)
	@$(PERL) $(TOP_crypto_cmac)/util/mklink.pl ../../apps $(APPS_crypto_cmac)

install: install_crypto_cmac
install_crypto_cmac:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_cmac)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cmac
tags_crypto_cmac:
	ctags $(SRC_crypto_cmac)

tests: tests_crypto_cmac
tests_crypto_cmac:

lint: lint_crypto_cmac
lint_crypto_cmac:
	lint -DLINT $(INCLUDES_crypto_cmac) $(SRC_crypto_cmac)>fluff

dclean: dclean_crypto_cmac
dclean_crypto_cmac:

clean: clean_crypto_cmac
clean_crypto_cmac:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_cmac) $(CPPFLAGS) -c -o $@ $<
