#
# OpenSSL/fips/hmac/Makefile
#

INCLUDES_fips_hmac=

CFLAGS_fips_hmac= $(INCLUDES_fips_hmac) $(CFLAG)

GENERAL_fips_hmac=fips/hmac/Makefile
TEST_fips_hmac=fips/hmac/fips_hmactest.c
APPS_fips_hmac=

LIB_fips_hmac=libcrypto.a
LIBSRC_fips_hmac= fips/hmac/fips_hmac_selftest.c
LIBOBJ_fips_hmac= fips/hmac/fips_hmac_selftest.o

SRC_fips_hmac= $(LIBSRC_fips_hmac)

EXHEADER_fips_hmac=
HEADER_fips_hmac=	$(EXHEADER_fips_hmac)

ALL_fips_hmac=    $(GENERAL_fips_hmac) $(SRC_fips_hmac) $(HEADER_fips_hmac)


all: all_fips_hmac
all_fips_hmac:	fips/hmac/lib

fips/hmac/lib:	$(LIBOBJ_fips_hmac)
	@echo $(LIBOBJ_fips_hmac) > fips/hmac/lib

files: files_fips_hmac
files_fips_hmac:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_hmac
links_fips_hmac:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_hmac)
	@$(PERL) util/mklink.pl test $(TEST_fips_hmac)
	@$(PERL) util/mklink.pl apps $(APPS_fips_hmac)

install: install_fips_hmac
install_fips_hmac:
	@headerlist="$(EXHEADER_fips_hmac)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_hmac
tags_fips_hmac:
	ctags $(SRC_fips_hmac)

tests: tests_fips_hmac
tests_fips_hmac:

Q_fips_hmac=../testvectors/hmac/req
A_fips_hmac=../testvectors/hmac/rsp

fips_test: fips_test_fips_hmac
fips_test_fips_hmac:
	-rm -rf $(A_fips_hmac)
	mkdir $(A_fips_hmac)
	if [ -f $(Q_fips_hmac)/HMAC.req ]; then util/shlib_wrap.sh test/fips_hmactest < $(Q_fips_hmac)/HMAC.req > $(A_fips_hmac)/HMAC.rsp; fi

lint: lint_fips_hmac
lint_fips_hmac:
	lint -DLINT $(INCLUDES_fips_hmac) $(SRC_fips_hmac)>fips/hmac/fluff

dclean: dclean_fips_hmac
dclean_fips_hmac:

clean: clean_fips_hmac
clean_fips_hmac:
	rm -f fips/hmac/*.o fips/hmac/*.d fips/hmac/*.obj fips/hmac/lib fips/hmac/tags fips/hmac/core fips/hmac/.pure fips/hmac/.nfs* fips/hmac/*.old fips/hmac/*.bak fips/hmac/fluff

