#
# OpenSSL/fips/ecdsa/Makefile
#

DIR_fips_ecdsa=	ecdsa
INCLUDES_fips_ecdsa=

CFLAGS_fips_ecdsa= $(INCLUDES_fips_ecdsa) $(CFLAG)

GENERAL_fips_ecdsa=Makefile
TEST_fips_ecdsa= fips_ecdsavs.c
APPS_fips_ecdsa=

LIB_fips_ecdsa=$(TOP_fips_ecdsa)/libcrypto.a
LIBSRC_fips_ecdsa= fips_ecdsa_lib.c fips_ecdsa_sign.c fips_ecdsa_selftest.c
LIBOBJ_fips_ecdsa= fips_ecdsa_lib.o fips_ecdsa_sign.o fips_ecdsa_selftest.o

SRC_fips_ecdsa= $(LIBSRC_fips_ecdsa)

EXHEADER_fips_ecdsa=
HEADER_fips_ecdsa=	$(EXHEADER_fips_ecdsa)

ALL_fips_ecdsa=    $(GENERAL_fips_ecdsa) $(SRC_fips_ecdsa) $(HEADER_fips_ecdsa)

top: top_fips_ecdsa
top_fips_ecdsa:
	(cd $(TOP_fips_ecdsa); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_ecdsa) sub_all)

all: all_fips_ecdsa
all_fips_ecdsa:	lib

lib:	$(LIBOBJ_fips_ecdsa)
	@echo $(LIBOBJ_fips_ecdsa) > lib

files: files_fips_ecdsa
files_fips_ecdsa:
	$(PERL) $(TOP_fips_ecdsa)/util/files.pl TOP=$(TOP_fips_ecdsa) Makefile >> $(TOP_fips_ecdsa)/MINFO

links: links_fips_ecdsa
links_fips_ecdsa:
	@$(PERL) $(TOP_fips_ecdsa)/util/mklink.pl $(TOP_fips_ecdsa)/include/openssl $(EXHEADER_fips_ecdsa)
	@$(PERL) $(TOP_fips_ecdsa)/util/mklink.pl $(TOP_fips_ecdsa)/test $(TEST_fips_ecdsa)
	@$(PERL) $(TOP_fips_ecdsa)/util/mklink.pl $(TOP_fips_ecdsa)/apps $(APPS_fips_ecdsa)

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
	lint -DLINT $(INCLUDES_fips_ecdsa) $(SRC_fips_ecdsa)>fluff

dclean: dclean_fips_ecdsa
dclean_fips_ecdsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_ecdsa
clean_fips_ecdsa:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_ecdsa) $(CPPFLAGS) -c -o $@ $<
