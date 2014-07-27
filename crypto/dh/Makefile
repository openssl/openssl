#
# OpenSSL/crypto/dh/Makefile
#

DIR_crypto_dh=	dh
INCLUDES_crypto_dh= -I.. -I$(TOP_crypto_dh) -I../../include

CFLAGS_crypto_dh= $(INCLUDES_crypto_dh) $(CFLAG)

GENERAL_crypto_dh=Makefile
TEST_crypto_dh= dhtest.c
APPS_crypto_dh=

LIB_crypto_dh=$(TOP_crypto_dh)/libcrypto.a
LIBSRC_crypto_dh= dh_asn1.c dh_gen.c dh_key.c dh_lib.c dh_check.c dh_err.c dh_depr.c \
	dh_ameth.c dh_pmeth.c dh_prn.c dh_rfc5114.c dh_kdf.c
LIBOBJ_crypto_dh= dh_asn1.o dh_gen.o dh_key.o dh_lib.o dh_check.o dh_err.o dh_depr.o \
	dh_ameth.o dh_pmeth.o dh_prn.o dh_rfc5114.o dh_kdf.o

SRC_crypto_dh= $(LIBSRC_crypto_dh)

EXHEADER_crypto_dh= dh.h
HEADER_crypto_dh=	$(EXHEADER_crypto_dh)

ALL_crypto_dh=    $(GENERAL_crypto_dh) $(SRC_crypto_dh) $(HEADER_crypto_dh)

top: top_crypto_dh
top_crypto_dh:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_dh) sub_all)

all: all_crypto_dh
all_crypto_dh:	lib

lib:	$(LIBOBJ_crypto_dh)
	$(ARX) $(LIB_crypto_dh) $(LIBOBJ_crypto_dh)
	$(RANLIB) $(LIB_crypto_dh) || echo Never mind.
	@touch lib

files: files_crypto_dh
files_crypto_dh:
	$(PERL) $(TOP_crypto_dh)/util/files.pl TOP=$(TOP_crypto_dh) Makefile >> $(TOP_crypto_dh)/MINFO

links: links_crypto_dh
links_crypto_dh:
	@$(PERL) $(TOP_crypto_dh)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_dh)
	@$(PERL) $(TOP_crypto_dh)/util/mklink.pl ../../test $(TEST_crypto_dh)
	@$(PERL) $(TOP_crypto_dh)/util/mklink.pl ../../apps $(APPS_crypto_dh)

install: install_crypto_dh
install_crypto_dh:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_dh)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_dh
tags_crypto_dh:
	ctags $(SRC_crypto_dh)

tests: tests_crypto_dh
tests_crypto_dh:

lint: lint_crypto_dh
lint_crypto_dh:
	lint -DLINT $(INCLUDES_crypto_dh) $(SRC_crypto_dh)>fluff

dclean: dclean_crypto_dh
dclean_crypto_dh:

clean: clean_crypto_dh
clean_crypto_dh:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_dh) $(CPPFLAGS) -c -o $@ $<
