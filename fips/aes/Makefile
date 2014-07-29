#
# OpenSSL/fips/aes/Makefile
#

INCLUDES_fips_aes=

ASFLAGS_fips_aes= $(INCLUDES_fips_aes) $(ASFLAG)
AFLAGS_fips_aes= $(ASFLAGS_fips_aes)

CFLAGS_fips_aes= $(INCLUDES_fips_aes) $(CFLAG)

GENERAL_fips_aes=fips/aes/Makefile
TEST_fips_aes=fips/aes/fips_aesavs.c fips/aes/fips_gcmtest.c
APPS_fips_aes=

LIB_fips_aes=libcrypto.a
LIBSRC_fips_aes=fips/aes/fips_aes_selftest.c
LIBOBJ_fips_aes=fips/aes/fips_aes_selftest.o

SRC_fips_aes= $(LIBSRC_fips_aes)

EXHEADER_fips_aes=
HEADER_fips_aes=

ALL_fips_aes=    $(GENERAL_fips_aes) $(SRC_fips_aes) $(HEADER_fips_aes)


all: all_fips_aes
all_fips_aes:	fips/aes/lib

fips/aes/lib:	$(LIBOBJ_fips_aes)
	@echo $(LIBOBJ_fips_aes) > fips/aes/lib

files: files_fips_aes
files_fips_aes:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_aes
links_fips_aes:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_aes)
	@$(PERL) util/mklink.pl test $(TEST_fips_aes)
	@$(PERL) util/mklink.pl apps $(APPS_fips_aes)

install: install_fips_aes
install_fips_aes:
	@headerlist="$(EXHEADER_fips_aes)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_aes
tags_fips_aes:
	ctags $(SRC_fips_aes)

tests: tests_fips_aes
tests_fips_aes:

fips_test: fips_test_fips_aes
fips_test_fips_aes:
	-find ../testvectors/aes/req -name '*.req' > testlist
	-rm -rf ../testvectors/aes/rsp
	mkdir ../testvectors/aes/rsp
	if [ -s testlist ]; then util/shlib_wrap.sh test/fips_aesavs -d testlist; fi

lint: lint_fips_aes
lint_fips_aes:
	lint -DLINT $(INCLUDES_fips_aes) $(SRC_fips_aes)>fips/aes/fluff

dclean: dclean_fips_aes
dclean_fips_aes:

clean: clean_fips_aes
clean_fips_aes:
	rm -f fips/aes/*.o fips/aes/*.d asm/*.o fips/aes/*.obj fips/aes/lib fips/aes/tags fips/aes/core fips/aes/.pure fips/aes/.nfs* fips/aes/*.old fips/aes/*.bak fips/aes/fluff fips/aes/testlist

.c.o:
	$(CC) $(CFLAGS_fips_aes) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips_aes) -o $@ $<
