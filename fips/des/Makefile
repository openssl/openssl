#
# OpenSSL/fips/des/Makefile
#

DIR_fips_des=	des
INCLUDES_fips_des=

ASFLAGS_fips_des= $(INCLUDES_fips_des) $(ASFLAG)
AFLAGS_fips_des= $(ASFLAGS_fips_des)

CFLAGS_fips_des= $(INCLUDES_fips_des) $(CFLAG)

GENERAL_fips_des=Makefile
TEST_fips_des= fips_desmovs.c
APPS_fips_des=

LIB_fips_des=$(TOP_fips_des)/libcrypto.a
LIBSRC_fips_des=fips_des_selftest.c
LIBOBJ_fips_des=fips_des_selftest.o

SRC_fips_des= $(LIBSRC_fips_des)

EXHEADER_fips_des=
HEADER_fips_des=

ALL_fips_des=    $(GENERAL_fips_des) $(SRC_fips_des) $(HEADER_fips_des)

top: top_fips_des
top_fips_des:
	(cd $(TOP_fips_des); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_des) sub_all)

all: all_fips_des
all_fips_des:	lib

lib:	$(LIBOBJ_fips_des)
	@echo $(LIBOBJ_fips_des) > lib

files: files_fips_des
files_fips_des:
	$(PERL) $(TOP_fips_des)/util/files.pl TOP=$(TOP_fips_des) Makefile >> $(TOP_fips_des)/MINFO

links: links_fips_des
links_fips_des:
	@$(PERL) $(TOP_fips_des)/util/mklink.pl $(TOP_fips_des)/include/openssl $(EXHEADER_fips_des)
	@$(PERL) $(TOP_fips_des)/util/mklink.pl $(TOP_fips_des)/test $(TEST_fips_des)
	@$(PERL) $(TOP_fips_des)/util/mklink.pl $(TOP_fips_des)/apps $(APPS_fips_des)

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
	if [ -s testlist ]; then $(TOP_fips_des)/util/shlib_wrap.sh $(TOP_fips_des)/test/fips_desmovs -d testlist; fi

lint: lint_fips_des
lint_fips_des:
	lint -DLINT $(INCLUDES_fips_des) $(SRC_fips_des)>fluff

dclean: dclean_fips_des
dclean_fips_des:

clean: clean_fips_des
clean_fips_des:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff testlist

.c.o:
	$(CC) $(CFLAGS_fips_des) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips_des) -o $@ $<
