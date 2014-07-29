#
# OpenSSL/fips/dh/Makefile
#

INCLUDES_fips_dh=

CFLAGS_fips_dh= $(INCLUDES_fips_dh) $(CFLAG)

GENERAL_fips_dh=fips/dh/Makefile
TEST_fips_dh= fips/dh/fips_dhvs.c
APPS_fips_dh=

LIB_fips_dh=libcrypto.a
LIBSRC_fips_dh= fips/dh/fips_dh_lib.c
LIBOBJ_fips_dh= fips/dh/fips_dh_lib.o

SRC_fips_dh= $(LIBSRC_fips_dh)

EXHEADER_fips_dh=
HEADER_fips_dh=	$(EXHEADER_fips_dh)

ALL_fips_dh=    $(GENERAL_fips_dh) $(SRC_fips_dh) $(HEADER_fips_dh)


all: all_fips_dh
all_fips_dh:	fips/dh/lib

fips/dh/lib:	$(LIBOBJ_fips_dh)
	@echo $(LIBOBJ_fips_dh) > fips/dh/lib

files: files_fips_dh
files_fips_dh:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_dh
links_fips_dh:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_dh)
	@$(PERL) util/mklink.pl test $(TEST_fips_dh)
	@$(PERL) util/mklink.pl apps $(APPS_fips_dh)

install: install_fips_dh
install_fips_dh:
	@headerlist="$(EXHEADER_fips_dh)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_dh
tags_fips_dh:
	ctags $(SRC_fips_dh)

tests: tests_fips_dh
tests_fips_dh:

fips_test: fips_test_fips_dh
fips_test_fips_dh:

lint: lint_fips_dh
lint_fips_dh:
	lint -DLINT $(INCLUDES_fips_dh) $(SRC_fips_dh)>fips/dh/fluff

dclean: dclean_fips_dh
dclean_fips_dh:

clean: clean_fips_dh
clean_fips_dh:
	rm -f fips/dh/*.o fips/dh/*.d fips/dh/*.obj fips/dh/lib fips/dh/tags fips/dh/core fips/dh/.pure fips/dh/.nfs* fips/dh/*.old fips/dh/*.bak fips/dh/fluff

.c.o:
	$(CC) $(CFLAGS_fips_dh) $(CPPFLAGS) -c -o $@ $<
