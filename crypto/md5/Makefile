#
# OpenSSL/crypto/md5/Makefile
#

DIR_crypto_md5=    md5
CPP_crypto_md5=    $(CC) -E
INCLUDES_crypto_md5=-I.. -I$(TOP_crypto_md5) -I../../include


CFLAGS_crypto_md5= $(INCLUDES_crypto_md5) $(CFLAG)
ASFLAGS_crypto_md5= $(INCLUDES_crypto_md5) $(ASFLAG)
AFLAGS_crypto_md5= $(ASFLAGS_crypto_md5)

GENERAL_crypto_md5=Makefile
TEST_crypto_md5=md5test.c
APPS_crypto_md5=

LIB_crypto_md5=$(TOP_crypto_md5)/libcrypto.a
LIBSRC_crypto_md5=md5_dgst.c md5_one.c
LIBOBJ_crypto_md5=md5_dgst.o md5_one.o $(MD5_ASM_OBJ)

SRC_crypto_md5= $(LIBSRC_crypto_md5)

EXHEADER_crypto_md5= md5.h
HEADER_crypto_md5= md5_locl.h $(EXHEADER_crypto_md5)

ALL_crypto_md5=    $(GENERAL_crypto_md5) $(SRC_crypto_md5) $(HEADER_crypto_md5)

top: top_crypto_md5
top_crypto_md5:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_md5) sub_all)

all: all_crypto_md5
all_crypto_md5:    lib

lib: lib_crypto_md5
lib_crypto_md5:    $(LIBOBJ_crypto_md5)
	$(ARX) $(LIB_crypto_md5) $(LIBOBJ_crypto_md5)
	$(RANLIB) $(LIB_crypto_md5) || echo Never mind.
	@touch lib

md5-586.s:	asm/md5-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/md5-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_md5) > $@

md5-x86_64.s:	asm/md5-x86_64.pl
	$(PERL) asm/md5-x86_64.pl $(PERLASM_SCHEME) > $@

md5-ia64.s: asm/md5-ia64.S
	$(CC) $(CFLAGS_crypto_md5) -E asm/md5-ia64.S | \
	$(PERL) -ne 's/;\s+/;\n/g; print;' > $@

md5-sparcv9.S:	asm/md5-sparcv9.pl
	$(PERL) asm/md5-sparcv9.pl $@ $(CFLAGS_crypto_md5)

files: files_crypto_md5
files_crypto_md5:
	$(PERL) $(TOP_crypto_md5)/util/files.pl TOP=$(TOP_crypto_md5) Makefile >> $(TOP_crypto_md5)/MINFO

links: links_crypto_md5
links_crypto_md5:
	@$(PERL) $(TOP_crypto_md5)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_md5)
	@$(PERL) $(TOP_crypto_md5)/util/mklink.pl ../../test $(TEST_crypto_md5)
	@$(PERL) $(TOP_crypto_md5)/util/mklink.pl ../../apps $(APPS_crypto_md5)

install: install_crypto_md5
install_crypto_md5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_md5)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_md5
tags_crypto_md5:
	ctags $(SRC_crypto_md5)

tests: tests_crypto_md5
tests_crypto_md5:

lint: lint_crypto_md5
lint_crypto_md5:
	lint -DLINT $(INCLUDES_crypto_md5) $(SRC_crypto_md5)>fluff

dclean: dclean_crypto_md5
dclean_crypto_md5:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_md5
clean_crypto_md5:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_md5) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_md5) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_md5) -o $@ $<
