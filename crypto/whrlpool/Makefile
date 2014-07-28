#
# crypto/whrlpool/Makefile
#

DIR_crypto_whrlpool=	whrlpool
CPP_crypto_whrlpool=	$(CC) -E
INCLUDES_crypto_whrlpool=


CFLAGS_crypto_whrlpool= $(INCLUDES_crypto_whrlpool) $(CFLAG)
ASFLAGS_crypto_whrlpool= $(INCLUDES_crypto_whrlpool) $(ASFLAG)
AFLAGS_crypto_whrlpool= $(ASFLAGS_crypto_whrlpool)

GENERAL_crypto_whrlpool=Makefile
TEST_crypto_whrlpool=wp_test.c
APPS_crypto_whrlpool=

LIB_crypto_whrlpool=$(TOP_crypto_whrlpool)/libcrypto.a
LIBSRC_crypto_whrlpool=wp_dgst.c wp_block.c
LIBOBJ_crypto_whrlpool=wp_dgst.o $(WP_ASM_OBJ)

SRC_crypto_whrlpool= $(LIBSRC_crypto_whrlpool)

EXHEADER_crypto_whrlpool= whrlpool.h
HEADER_crypto_whrlpool= wp_locl.h $(EXHEADER_crypto_whrlpool)

ALL_crypto_whrlpool=    $(GENERAL_crypto_whrlpool) $(SRC_crypto_whrlpool) $(HEADER_crypto_whrlpool)

top: top_crypto_whrlpool
top_crypto_whrlpool:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_whrlpool) sub_all)

all: all_crypto_whrlpool
all_crypto_whrlpool:	lib

lib:	$(LIBOBJ_crypto_whrlpool)
	$(ARX) $(LIB_crypto_whrlpool) $(LIBOBJ_crypto_whrlpool)
	$(RANLIB) $(LIB_crypto_whrlpool) || echo Never mind.
	@touch lib

wp-mmx.s:	asm/wp-mmx.pl ../perlasm/x86asm.pl
	$(PERL) asm/wp-mmx.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_whrlpool) $(PROCESSOR) > $@

wp-x86_64.s: asm/wp-x86_64.pl
	$(PERL) asm/wp-x86_64.pl $(PERLASM_SCHEME) > $@

$(LIBOBJ_crypto_whrlpool): $(LIBSRC_crypto_whrlpool)

files: files_crypto_whrlpool
files_crypto_whrlpool:
	$(PERL) $(TOP_crypto_whrlpool)/util/files.pl TOP=$(TOP_crypto_whrlpool) Makefile >> $(TOP_crypto_whrlpool)/MINFO

links: links_crypto_whrlpool
links_crypto_whrlpool:
	@$(PERL) $(TOP_crypto_whrlpool)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_whrlpool)
	@$(PERL) $(TOP_crypto_whrlpool)/util/mklink.pl ../../test $(TEST_crypto_whrlpool)
	@$(PERL) $(TOP_crypto_whrlpool)/util/mklink.pl ../../apps $(APPS_crypto_whrlpool)

install: install_crypto_whrlpool
install_crypto_whrlpool:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_whrlpool)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_whrlpool
tags_crypto_whrlpool:
	ctags $(SRC_crypto_whrlpool)

tests: tests_crypto_whrlpool
tests_crypto_whrlpool:

lint: lint_crypto_whrlpool
lint_crypto_whrlpool:
	lint -DLINT $(INCLUDES_crypto_whrlpool) $(SRC_crypto_whrlpool)>fluff

dclean: dclean_crypto_whrlpool
dclean_crypto_whrlpool:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_whrlpool
clean_crypto_whrlpool:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_whrlpool) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_whrlpool) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_whrlpool) -o $@ $<
