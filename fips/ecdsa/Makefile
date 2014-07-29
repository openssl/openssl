#
# OpenSSL/fips/ecdsa/Makefile
#

INCLUDES_fips_ecdsa=

CFLAGS_fips_ecdsa= $(INCLUDES_fips_ecdsa) $(CFLAG)

GENERAL_fips_ecdsa=fips/ecdsa/Makefile
TEST_fips_ecdsa= fips/ecdsa/fips_ecdsavs.c
APPS_fips_ecdsa=

LIB_fips_ecdsa=libcrypto.a
LIBSRC_fips_ecdsa= fips/ecdsa/fips_ecdsa_lib.c fips/ecdsa/fips_ecdsa_sign.c fips/ecdsa/fips_ecdsa_selftest.c
LIBOBJ_fips_ecdsa= fips/ecdsa/fips_ecdsa_lib.o fips/ecdsa/fips_ecdsa_sign.o fips/ecdsa/fips_ecdsa_selftest.o

SRC_fips_ecdsa= $(LIBSRC_fips_ecdsa)

EXHEADER_fips_ecdsa=
HEADER_fips_ecdsa=	$(EXHEADER_fips_ecdsa)

ALL_fips_ecdsa=    $(GENERAL_fips_ecdsa) $(SRC_fips_ecdsa) $(HEADER_fips_ecdsa)


all: all_fips_ecdsa
all_fips_ecdsa:	fips/ecdsa/lib

fips/ecdsa/lib:	$(LIBOBJ_fips_ecdsa)
	@echo $(LIBOBJ_fips_ecdsa) > fips/ecdsa/lib

files: files_fips_ecdsa
files_fips_ecdsa:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_ecdsa
links_fips_ecdsa:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_ecdsa)
	@$(PERL) util/mklink.pl test $(TEST_fips_ecdsa)
	@$(PERL) util/mklink.pl apps $(APPS_fips_ecdsa)

install: install_fips_ecdsa
install_fips_ecdsa:
	@headerlist="$(EXHEADER_fips_ecdsa)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_ecdsa
tags_fips_ecdsa:
	ctags $(SRC_fips_ecdsa)

tests: tests_fips_ecdsa
tests_fips_ecdsa:

fips_test: fips_test_fips_ecdsa
fips_test_fips_ecdsa:

lint: lint_fips_ecdsa
lint_fips_ecdsa:
	lint -DLINT $(INCLUDES_fips_ecdsa) $(SRC_fips_ecdsa)>fips/ecdsa/fluff

dclean: dclean_fips_ecdsa
dclean_fips_ecdsa:

clean: clean_fips_ecdsa
clean_fips_ecdsa:
	rm -f fips/ecdsa/*.o fips/ecdsa/*.d fips/ecdsa/*.obj fips/ecdsa/lib fips/ecdsa/tags fips/ecdsa/core fips/ecdsa/.pure fips/ecdsa/.nfs* fips/ecdsa/*.old fips/ecdsa/*.bak fips/ecdsa/fluff

.c.o:
	$(CC) $(CFLAGS_fips_ecdsa) $(CPPFLAGS) -c -o $@ $<
