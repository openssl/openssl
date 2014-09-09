#
# OpenSSL/fips/ecdh/Makefile
#

INCLUDES_fips_ecdh=

CFLAGS_fips_ecdh= $(INCLUDES_fips_ecdh) $(CFLAG)

GENERAL_fips_ecdh=fips/ecdh/Makefile
TEST_fips_ecdh= fips/ecdh/fips_ecdhvs.c
APPS_fips_ecdh=

LIB_fips_ecdh=libcrypto.a
LIBSRC_fips_ecdh= fips/ecdh/fips_ecdh_selftest.c
LIBOBJ_fips_ecdh= fips/ecdh/fips_ecdh_selftest.o

SRC_fips_ecdh= $(LIBSRC_fips_ecdh)

EXHEADER_fips_ecdh=
HEADER_fips_ecdh=	$(EXHEADER_fips_ecdh)

ALL_fips_ecdh=    $(GENERAL_fips_ecdh) $(SRC_fips_ecdh) $(HEADER_fips_ecdh)


all: all_fips_ecdh
all_fips_ecdh:	fips/ecdh/lib

fips/ecdh/lib:	$(LIBOBJ_fips_ecdh)
	@echo $(LIBOBJ_fips_ecdh) > fips/ecdh/lib

files: files_fips_ecdh
files_fips_ecdh:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_ecdh
links_fips_ecdh:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_ecdh)
	@$(PERL) util/mklink.pl test $(TEST_fips_ecdh)
	@$(PERL) util/mklink.pl apps $(APPS_fips_ecdh)

install: install_fips_ecdh
install_fips_ecdh:
	@headerlist="$(EXHEADER_fips_ecdh)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_ecdh
tags_fips_ecdh:
	ctags $(SRC_fips_ecdh)

tests: tests_fips_ecdh
tests_fips_ecdh:

fips_test: fips_test_fips_ecdh
fips_test_fips_ecdh:

lint: lint_fips_ecdh
lint_fips_ecdh:
	lint -DLINT $(INCLUDES_fips_ecdh) $(SRC_fips_ecdh)>fips/ecdh/fluff

dclean: dclean_fips_ecdh
dclean_fips_ecdh:

clean: clean_fips_ecdh
clean_fips_ecdh:
	rm -f fips/ecdh/*.o fips/ecdh/*.d fips/ecdh/*.obj fips/ecdh/lib fips/ecdh/tags fips/ecdh/core fips/ecdh/.pure fips/ecdh/.nfs* fips/ecdh/*.old fips/ecdh/*.bak fips/ecdh/fluff

