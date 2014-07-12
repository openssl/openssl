#
# OpenSSL/crypto/ripemd/Makefile
#

DIR_crypto_ripemd=    ripemd
CPP_crypto_ripemd=    $(CC) -E
INCLUDES_crypto_ripemd=

RIP_ASM_OBJ=

CFLAGS_crypto_ripemd= $(INCLUDES_crypto_ripemd) $(CFLAG)
ASFLAGS_crypto_ripemd= $(INCLUDES_crypto_ripemd) $(ASFLAG)
AFLAGS_crypto_ripemd= $(ASFLAGS_crypto_ripemd)

GENERAL_crypto_ripemd=Makefile
TEST_crypto_ripemd=rmdtest.c
APPS_crypto_ripemd=

LIB_crypto_ripemd=$(TOP_crypto_ripemd)/libcrypto.a
LIBSRC_crypto_ripemd=rmd_dgst.c rmd_one.c
LIBOBJ_crypto_ripemd=rmd_dgst.o rmd_one.o $(RMD160_ASM_OBJ)

SRC_crypto_ripemd= $(LIBSRC_crypto_ripemd)

EXHEADER_crypto_ripemd= ripemd.h
HEADER_crypto_ripemd= rmd_locl.h rmdconst.h $(EXHEADER_crypto_ripemd)

ALL_crypto_ripemd=    $(GENERAL_crypto_ripemd) $(SRC_crypto_ripemd) $(HEADER_crypto_ripemd)

top: top_crypto_ripemd
top_crypto_ripemd:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_ripemd) sub_all)

all: all_crypto_ripemd
all_crypto_ripemd:    lib

lib: lib_crypto_ripemd
lib_crypto_ripemd:    $(LIBOBJ_crypto_ripemd)
	$(ARX) $(LIB_crypto_ripemd) $(LIBOBJ_crypto_ripemd)
	$(RANLIB) $(LIB_crypto_ripemd) || echo Never mind.
	@touch lib

rmd-586.s:	asm/rmd-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/rmd-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_ripemd) > $@

files: files_crypto_ripemd
files_crypto_ripemd:
	$(PERL) $(TOP_crypto_ripemd)/util/files.pl TOP=$(TOP_crypto_ripemd) Makefile >> $(TOP_crypto_ripemd)/MINFO

links: links_crypto_ripemd
links_crypto_ripemd:
	@$(PERL) $(TOP_crypto_ripemd)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ripemd)
	@$(PERL) $(TOP_crypto_ripemd)/util/mklink.pl ../../test $(TEST_crypto_ripemd)
	@$(PERL) $(TOP_crypto_ripemd)/util/mklink.pl ../../apps $(APPS_crypto_ripemd)

install: install_crypto_ripemd
install_crypto_ripemd:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ripemd)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ripemd
tags_crypto_ripemd:
	ctags $(SRC_crypto_ripemd)

tests: tests_crypto_ripemd
tests_crypto_ripemd:

lint: lint_crypto_ripemd
lint_crypto_ripemd:
	lint -DLINT $(INCLUDES_crypto_ripemd) $(SRC_crypto_ripemd)>fluff

dclean: dclean_crypto_ripemd
dclean_crypto_ripemd:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_ripemd
clean_crypto_ripemd:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_ripemd) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_ripemd) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_ripemd) -o $@ $<
