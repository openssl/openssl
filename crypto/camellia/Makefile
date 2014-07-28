#
# crypto/camellia/Makefile
#

DIR_crypto_camellia= camellia
CPP_crypto_camellia=	$(CC) -E
INCLUDES_crypto_camellia=


CFLAGS_crypto_camellia= $(INCLUDES_crypto_camellia) $(CFLAG)
ASFLAGS_crypto_camellia= $(INCLUDES_crypto_camellia) $(ASFLAG)
AFLAGS_crypto_camellia= $(ASFLAGS_crypto_camellia)

GENERAL_crypto_camellia=Makefile
#TEST=camelliatest.c
APPS_crypto_camellia=

LIB_crypto_camellia=$(TOP_crypto_camellia)/libcrypto.a
LIBSRC_crypto_camellia=camellia.c cmll_misc.c cmll_ecb.c cmll_cbc.c cmll_ofb.c \
	   cmll_cfb.c cmll_ctr.c 

LIBOBJ_crypto_camellia= cmll_ecb.o cmll_ofb.o cmll_cfb.o cmll_ctr.o $(CMLL_ENC)

SRC_crypto_camellia= $(LIBSRC_crypto_camellia)

EXHEADER_crypto_camellia= camellia.h
HEADER_crypto_camellia= cmll_locl.h $(EXHEADER_crypto_camellia)

ALL_crypto_camellia=    $(GENERAL_crypto_camellia) $(SRC_crypto_camellia) $(HEADER_crypto_camellia)

top: top_crypto_camellia
top_crypto_camellia:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_camellia) sub_all)

all: all_crypto_camellia
all_crypto_camellia:	lib

lib:	$(LIBOBJ_crypto_camellia)
	$(ARX) $(LIB_crypto_camellia) $(LIBOBJ_crypto_camellia)
	$(RANLIB) $(LIB_crypto_camellia) || echo Never mind.
	@touch lib

cmll-x86.s:	asm/cmll-x86.pl ../perlasm/x86asm.pl
	$(PERL) asm/cmll-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_camellia) $(PROCESSOR) > $@
cmll-x86_64.s:  asm/cmll-x86_64.pl
	$(PERL) asm/cmll-x86_64.pl $(PERLASM_SCHEME) > $@
cmllt4-sparcv9.s: asm/cmllt4-sparcv9.pl
	$(PERL) asm/cmllt4-sparcv9.pl $(CFLAGS_crypto_camellia) > $@

files: files_crypto_camellia
files_crypto_camellia:
	$(PERL) $(TOP_crypto_camellia)/util/files.pl TOP=$(TOP_crypto_camellia) Makefile >> $(TOP_crypto_camellia)/MINFO

links: links_crypto_camellia
links_crypto_camellia:
	@$(PERL) $(TOP_crypto_camellia)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_camellia)
	@$(PERL) $(TOP_crypto_camellia)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP_crypto_camellia)/util/mklink.pl ../../apps $(APPS_crypto_camellia)

install: install_crypto_camellia
install_crypto_camellia:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_camellia)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_camellia
tags_crypto_camellia:
	ctags $(SRC_crypto_camellia)

tests: tests_crypto_camellia
tests_crypto_camellia:

lint: lint_crypto_camellia
lint_crypto_camellia:
	lint -DLINT $(INCLUDES_crypto_camellia) $(SRC_crypto_camellia)>fluff

dclean: dclean_crypto_camellia
dclean_crypto_camellia:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_camellia
clean_crypto_camellia:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_camellia) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_camellia) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_camellia) -o $@ $<
