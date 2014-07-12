#
# crypto/whrlpool/Makefile
#

DIR=	whrlpool
CPP=	$(CC) -E
INCLUDES=


CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=wp_test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=wp_dgst.c wp_block.c
LIBOBJ=wp_dgst.o $(WP_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= whrlpool.h
HEADER= wp_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_whrlpool
top_crypto_whrlpool:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_whrlpool
all_crypto_whrlpool:	lib

lib: lib_crypto_whrlpool
lib_crypto_whrlpool:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

wp-mmx.s:	asm/wp-mmx.pl ../perlasm/x86asm.pl
	$(PERL) asm/wp-mmx.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

wp-x86_64.s: asm/wp-x86_64.pl
	$(PERL) asm/wp-x86_64.pl $(PERLASM_SCHEME) > $@

$(LIBOBJ): $(LIBSRC)

files: files_crypto_whrlpool
files_crypto_whrlpool:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_whrlpool
links_crypto_whrlpool:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_whrlpool
install_crypto_whrlpool:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_whrlpool
tags_crypto_whrlpool:
	ctags $(SRC)

tests: tests_crypto_whrlpool
tests_crypto_whrlpool:

lint: lint_crypto_whrlpool
lint_crypto_whrlpool:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_whrlpool
dclean_crypto_whrlpool:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_whrlpool
clean_crypto_whrlpool:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

