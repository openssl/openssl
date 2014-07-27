#
# OpenSSL/fips/dh/Makefile
#

DIR_fips_dh=	dh
INCLUDES_fips_dh=

CFLAGS_fips_dh= $(INCLUDES_fips_dh) $(CFLAG)

GENERAL_fips_dh=Makefile
TEST_fips_dh= fips_dhvs.c
APPS_fips_dh=

LIB_fips_dh=$(TOP_fips_dh)/libcrypto.a
LIBSRC_fips_dh= fips_dh_lib.c
LIBOBJ_fips_dh= fips_dh_lib.o

SRC_fips_dh= $(LIBSRC_fips_dh)

EXHEADER_fips_dh=
HEADER_fips_dh=	$(EXHEADER_fips_dh)

ALL_fips_dh=    $(GENERAL_fips_dh) $(SRC_fips_dh) $(HEADER_fips_dh)

top: top_fips_dh
top_fips_dh:
	(cd $(TOP_fips_dh); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_dh) sub_all)

all: all_fips_dh
all_fips_dh:	lib

lib:	$(LIBOBJ_fips_dh)
	@echo $(LIBOBJ_fips_dh) > lib

files: files_fips_dh
files_fips_dh:
	$(PERL) $(TOP_fips_dh)/util/files.pl TOP=$(TOP_fips_dh) Makefile >> $(TOP_fips_dh)/MINFO

links: links_fips_dh
links_fips_dh:
	@$(PERL) $(TOP_fips_dh)/util/mklink.pl $(TOP_fips_dh)/include/openssl $(EXHEADER_fips_dh)
	@$(PERL) $(TOP_fips_dh)/util/mklink.pl $(TOP_fips_dh)/test $(TEST_fips_dh)
	@$(PERL) $(TOP_fips_dh)/util/mklink.pl $(TOP_fips_dh)/apps $(APPS_fips_dh)

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
	lint -DLINT $(INCLUDES_fips_dh) $(SRC_fips_dh)>fluff

dclean: dclean_fips_dh
dclean_fips_dh:

clean: clean_fips_dh
clean_fips_dh:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_dh) $(CPPFLAGS) -c -o $@ $<
