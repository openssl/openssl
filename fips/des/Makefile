#
# OpenSSL/fips/des/Makefile
#

INCLUDES_fips_des=

ASFLAGS_fips_des= $(INCLUDES_fips_des) $(ASFLAG)
AFLAGS_fips_des= $(ASFLAGS_fips_des)

CFLAGS_fips_des= $(INCLUDES_fips_des) $(CFLAG)

GENERAL_fips_des=fips/des/Makefile
TEST_fips_des= fips/des/fips_desmovs.c
APPS_fips_des=

LIB_fips_des=libcrypto.a
LIBSRC_fips_des=fips/des/fips_des_selftest.c
LIBOBJ_fips_des=fips/des/fips_des_selftest.o

SRC_fips_des= $(LIBSRC_fips_des)

EXHEADER_fips_des=
HEADER_fips_des=

ALL_fips_des=    $(GENERAL_fips_des) $(SRC_fips_des) $(HEADER_fips_des)


all: all_fips_des
all_fips_des:	fips/des/lib

fips/des/lib:	$(LIBOBJ_fips_des)
	@echo $(LIBOBJ_fips_des) > fips/des/lib

files: files_fips_des
files_fips_des:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_des
links_fips_des:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_des)
	@$(PERL) util/mklink.pl test $(TEST_fips_des)
	@$(PERL) util/mklink.pl apps $(APPS_fips_des)

install: install_fips_des
install_fips_des:
	@headerlist="$(EXHEADER_fips_des)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_des
tags_fips_des:
	ctags $(SRC_fips_des)

tests: tests_fips_des
tests_fips_des:

fips_test: fips_test_fips_des
fips_test_fips_des:
	-find ../testvectors/tdes/req -name '*.req' > testlist
	-rm -rf ../testvectors/tdes/rsp
	mkdir ../testvectors/tdes/rsp
	if [ -s testlist ]; then util/shlib_wrap.sh test/fips_desmovs -d testlist; fi

lint: lint_fips_des
lint_fips_des:
	lint -DLINT $(INCLUDES_fips_des) $(SRC_fips_des)>fips/des/fluff

dclean: dclean_fips_des
dclean_fips_des:

clean: clean_fips_des
clean_fips_des:
	rm -f fips/des/*.o fips/des/*.d asm/*.o fips/des/*.obj fips/des/lib fips/des/tags fips/des/core fips/des/.pure fips/des/.nfs* fips/des/*.old fips/des/*.bak fips/des/fluff fips/des/testlist

.c.o:
	$(CC) $(CFLAGS_fips_des) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips_des) -o $@ $<
