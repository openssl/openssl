#
# OpenSSL/fips/cmac/Makefile
#

INCLUDES_fips_cmac=

CFLAGS_fips_cmac= $(INCLUDES_fips_cmac) $(CFLAG)

GENERAL_fips_cmac=fips/cmac/Makefile
TEST_fips_cmac=fips/cmac/fips_cmactest.c
APPS_fips_cmac=

LIB_fips_cmac=libcrypto.a
LIBSRC_fips_cmac= fips/cmac/fips_cmac_selftest.c
LIBOBJ_fips_cmac= fips/cmac/fips_cmac_selftest.o

SRC_fips_cmac= $(LIBSRC_fips_cmac)

EXHEADER_fips_cmac=
HEADER_fips_cmac=	$(EXHEADER_fips_cmac)

ALL_fips_cmac=    $(GENERAL_fips_cmac) $(SRC_fips_cmac) $(HEADER_fips_cmac)


all: all_fips_cmac
all_fips_cmac:	fips/cmac/lib

fips/cmac/lib:	$(LIBOBJ_fips_cmac)
	@echo $(LIBOBJ_fips_cmac) > fips/cmac/lib

files: files_fips_cmac
files_fips_cmac:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_cmac
links_fips_cmac:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_cmac)
	@$(PERL) util/mklink.pl test $(TEST_fips_cmac)
	@$(PERL) util/mklink.pl apps $(APPS_fips_cmac)

install: install_fips_cmac
install_fips_cmac:
	@headerlist="$(EXHEADER_fips_cmac)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_cmac
tags_fips_cmac:
	ctags $(SRC_fips_cmac)

tests: tests_fips_cmac
tests_fips_cmac:

Q_fips_cmac=../testvectors/cmac/req
A_fips_cmac=../testvectors/cmac/rsp

fips_test: fips_test_fips_cmac
fips_test_fips_cmac:
	-rm -rf $(A_fips_cmac)
	mkdir $(A_fips_cmac)
	if [ -f $(Q_fips_cmac)/CMACGenAES256.req ]; then util/shlib_wrap.sh test/fips_cmactest -g < $(Q_fips_cmac)/CMACGenAES256.req > $(A_fips_cmac)/CMACGenAES256.rsp; fi
	if [ -f $(Q_fips_cmac)/CMACVerAES256.req ]; then util/shlib_wrap.sh test/fips_cmactest -v < $(Q_fips_cmac)/CMACVerAES256.req > $(A_fips_cmac)/CMACVerAES256.rsp; fi

lint: lint_fips_cmac
lint_fips_cmac:
	lint -DLINT $(INCLUDES_fips_cmac) $(SRC_fips_cmac)>fips/cmac/fluff

dclean: dclean_fips_cmac
dclean_fips_cmac:

clean: clean_fips_cmac
clean_fips_cmac:
	rm -f fips/cmac/*.o fips/cmac/*.d fips/cmac/*.obj fips/cmac/lib fips/cmac/tags fips/cmac/core fips/cmac/.pure fips/cmac/.nfs* fips/cmac/*.old fips/cmac/*.bak fips/cmac/fluff

