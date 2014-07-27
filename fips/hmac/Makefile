#
# OpenSSL/fips/hmac/Makefile
#

DIR_fips_hmac=	hmac
INCLUDES_fips_hmac=

CFLAGS_fips_hmac= $(INCLUDES_fips_hmac) $(CFLAG)

GENERAL_fips_hmac=Makefile
TEST_fips_hmac=fips_hmactest.c
APPS_fips_hmac=

LIB_fips_hmac=$(TOP_fips_hmac)/libcrypto.a
LIBSRC_fips_hmac= fips_hmac_selftest.c
LIBOBJ_fips_hmac= fips_hmac_selftest.o

SRC_fips_hmac= $(LIBSRC_fips_hmac)

EXHEADER_fips_hmac=
HEADER_fips_hmac=	$(EXHEADER_fips_hmac)

ALL_fips_hmac=    $(GENERAL_fips_hmac) $(SRC_fips_hmac) $(HEADER_fips_hmac)

top: top_fips_hmac
top_fips_hmac:
	(cd $(TOP_fips_hmac); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_hmac) sub_all)

all: all_fips_hmac
all_fips_hmac:	lib

lib:	$(LIBOBJ_fips_hmac)
	@echo $(LIBOBJ_fips_hmac) > lib

files: files_fips_hmac
files_fips_hmac:
	$(PERL) $(TOP_fips_hmac)/util/files.pl TOP=$(TOP_fips_hmac) Makefile >> $(TOP_fips_hmac)/MINFO

links: links_fips_hmac
links_fips_hmac:
	@$(PERL) $(TOP_fips_hmac)/util/mklink.pl $(TOP_fips_hmac)/include/openssl $(EXHEADER_fips_hmac)
	@$(PERL) $(TOP_fips_hmac)/util/mklink.pl $(TOP_fips_hmac)/test $(TEST_fips_hmac)
	@$(PERL) $(TOP_fips_hmac)/util/mklink.pl $(TOP_fips_hmac)/apps $(APPS_fips_hmac)

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
	if [ -f $(Q_fips_hmac)/HMAC.req ]; then $(TOP_fips_hmac)/util/shlib_wrap.sh $(TOP_fips_hmac)/test/fips_hmactest < $(Q_fips_hmac)/HMAC.req > $(A_fips_hmac)/HMAC.rsp; fi

lint: lint_fips_hmac
lint_fips_hmac:
	lint -DLINT $(INCLUDES_fips_hmac) $(SRC_fips_hmac)>fluff

dclean: dclean_fips_hmac
dclean_fips_hmac:

clean: clean_fips_hmac
clean_fips_hmac:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_hmac) $(CPPFLAGS) -c -o $@ $<
