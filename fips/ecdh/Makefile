#
# OpenSSL/fips/ecdh/Makefile
#

INCLUDES_fips_ecdh=

CFLAGS_fips_ecdh= $(INCLUDES_fips_ecdh) $(CFLAG)

GENERAL_fips_ecdh=Makefile
TEST_fips_ecdh= fips_ecdhvs.c
APPS_fips_ecdh=

LIB_fips_ecdh=$(TOP_fips_ecdh)/libcrypto.a
LIBSRC_fips_ecdh= fips_ecdh_selftest.c
LIBOBJ_fips_ecdh= fips_ecdh_selftest.o

SRC_fips_ecdh= $(LIBSRC_fips_ecdh)

EXHEADER_fips_ecdh=
HEADER_fips_ecdh=	$(EXHEADER_fips_ecdh)

ALL_fips_ecdh=    $(GENERAL_fips_ecdh) $(SRC_fips_ecdh) $(HEADER_fips_ecdh)


all: all_fips_ecdh
all_fips_ecdh:	lib

lib:	$(LIBOBJ_fips_ecdh)
	@echo $(LIBOBJ_fips_ecdh) > lib

files: files_fips_ecdh
files_fips_ecdh:
	$(PERL) $(TOP_fips_ecdh)/util/files.pl TOP=$(TOP_fips_ecdh) Makefile >> $(TOP_fips_ecdh)/MINFO

links: links_fips_ecdh
links_fips_ecdh:
	@$(PERL) $(TOP_fips_ecdh)/util/mklink.pl $(TOP_fips_ecdh)/include/openssl $(EXHEADER_fips_ecdh)
	@$(PERL) $(TOP_fips_ecdh)/util/mklink.pl $(TOP_fips_ecdh)/test $(TEST_fips_ecdh)
	@$(PERL) $(TOP_fips_ecdh)/util/mklink.pl $(TOP_fips_ecdh)/apps $(APPS_fips_ecdh)

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
	lint -DLINT $(INCLUDES_fips_ecdh) $(SRC_fips_ecdh)>fluff

dclean: dclean_fips_ecdh
dclean_fips_ecdh:

clean: clean_fips_ecdh
clean_fips_ecdh:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_ecdh) $(CPPFLAGS) -c -o $@ $<
