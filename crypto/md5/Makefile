#
# OpenSSL/crypto/md5/Makefile
#

DIR=    md5
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include


CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=md5test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md5_dgst.c md5_one.c
LIBOBJ=md5_dgst.o md5_one.o $(MD5_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= md5.h
HEADER= md5_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_md5
top_crypto_md5:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_md5
all_crypto_md5:    lib

lib: lib_crypto_md5
lib_crypto_md5:    $(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

md5-586.s:	asm/md5-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/md5-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

md5-x86_64.s:	asm/md5-x86_64.pl
	$(PERL) asm/md5-x86_64.pl $(PERLASM_SCHEME) > $@

md5-ia64.s: asm/md5-ia64.S
	$(CC) $(CFLAGS) -E asm/md5-ia64.S | \
	$(PERL) -ne 's/;\s+/;\n/g; print;' > $@

md5-sparcv9.S:	asm/md5-sparcv9.pl
	$(PERL) asm/md5-sparcv9.pl $@ $(CFLAGS)

files: files_crypto_md5
files_crypto_md5:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_md5
links_crypto_md5:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_md5
install_crypto_md5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_md5
tags_crypto_md5:
	ctags $(SRC)

tests: tests_crypto_md5
tests_crypto_md5:

lint: lint_crypto_md5
lint_crypto_md5:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_md5
dclean_crypto_md5:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_md5
clean_crypto_md5:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

