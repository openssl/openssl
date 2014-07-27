#
# OpenSSL/fips/aes/Makefile
#

DIR_fips_aes=	aes
INCLUDES_fips_aes=

ASFLAGS_fips_aes= $(INCLUDES_fips_aes) $(ASFLAG)
AFLAGS_fips_aes= $(ASFLAGS_fips_aes)

CFLAGS_fips_aes= $(INCLUDES_fips_aes) $(CFLAG)

GENERAL_fips_aes=Makefile
TEST_fips_aes=fips_aesavs.c fips_gcmtest.c
APPS_fips_aes=

LIB_fips_aes=$(TOP_fips_aes)/libcrypto.a
LIBSRC_fips_aes=fips_aes_selftest.c
LIBOBJ_fips_aes=fips_aes_selftest.o

SRC_fips_aes= $(LIBSRC_fips_aes)

EXHEADER_fips_aes=
HEADER_fips_aes=

ALL_fips_aes=    $(GENERAL_fips_aes) $(SRC_fips_aes) $(HEADER_fips_aes)

top: top_fips_aes
top_fips_aes:
	(cd $(TOP_fips_aes); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_aes) sub_all)

all: all_fips_aes
all_fips_aes:	lib

lib:	$(LIBOBJ_fips_aes)
	@echo $(LIBOBJ_fips_aes) > lib

files: files_fips_aes
files_fips_aes:
	$(PERL) $(TOP_fips_aes)/util/files.pl TOP=$(TOP_fips_aes) Makefile >> $(TOP_fips_aes)/MINFO

links: links_fips_aes
links_fips_aes:
	@$(PERL) $(TOP_fips_aes)/util/mklink.pl $(TOP_fips_aes)/include/openssl $(EXHEADER_fips_aes)
	@$(PERL) $(TOP_fips_aes)/util/mklink.pl $(TOP_fips_aes)/test $(TEST_fips_aes)
	@$(PERL) $(TOP_fips_aes)/util/mklink.pl $(TOP_fips_aes)/apps $(APPS_fips_aes)

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
	if [ -s testlist ]; then $(TOP_fips_aes)/util/shlib_wrap.sh $(TOP_fips_aes)/test/fips_aesavs -d testlist; fi

lint: lint_fips_aes
lint_fips_aes:
	lint -DLINT $(INCLUDES_fips_aes) $(SRC_fips_aes)>fluff

dclean: dclean_fips_aes
dclean_fips_aes:

clean: clean_fips_aes
clean_fips_aes:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff testlist

.c.o:
	$(CC) $(CFLAGS_fips_aes) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips_aes) -o $@ $<
