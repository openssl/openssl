#
# OpenSSL/crypto/modes/Makefile
#

DIR_crypto_modes=	modes
INCLUDES_crypto_modes= -I.. -I$(TOP_crypto_modes) -I../../include


CFLAGS_crypto_modes= $(INCLUDES_crypto_modes) $(CFLAG)
ASFLAGS_crypto_modes= $(INCLUDES_crypto_modes) $(ASFLAG)
AFLAGS_crypto_modes= $(ASFLAGS_crypto_modes)

GENERAL_crypto_modes=Makefile
TEST_crypto_modes=
APPS_crypto_modes=

LIB_crypto_modes=$(TOP_crypto_modes)/libcrypto.a
LIBSRC_crypto_modes= cbc128.c ctr128.c cts128.c cfb128.c ofb128.c gcm128.c \
	ccm128.c xts128.c wrap128.c
LIBOBJ_crypto_modes= cbc128.o ctr128.o cts128.o cfb128.o ofb128.o gcm128.o \
	ccm128.o xts128.o wrap128.o $(MODES_ASM_OBJ)

SRC_crypto_modes= $(LIBSRC_crypto_modes)

#EXHEADER= store.h str_compat.h
EXHEADER_crypto_modes= modes.h
HEADER_crypto_modes=	modes_lcl.h $(EXHEADER_crypto_modes)

ALL_crypto_modes=    $(GENERAL_crypto_modes) $(SRC_crypto_modes) $(HEADER_crypto_modes)

top: top_crypto_modes
top_crypto_modes:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_modes) sub_all)

all: all_crypto_modes
all_crypto_modes:	lib

lib:	$(LIBOBJ_crypto_modes)
	$(ARX) $(LIB_crypto_modes) $(LIBOBJ_crypto_modes)
	$(RANLIB) $(LIB_crypto_modes) || echo Never mind.
	@touch lib

ghash-ia64.s:	asm/ghash-ia64.pl
	$(PERL) asm/ghash-ia64.pl $@ $(CFLAGS_crypto_modes)
ghash-x86.s:	asm/ghash-x86.pl
	$(PERL) asm/ghash-x86.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_modes) $(PROCESSOR) > $@
ghash-x86_64.s:	asm/ghash-x86_64.pl
	$(PERL) asm/ghash-x86_64.pl $(PERLASM_SCHEME) > $@
aesni-gcm-x86_64.s:	asm/aesni-gcm-x86_64.pl
	$(PERL) asm/aesni-gcm-x86_64.pl $(PERLASM_SCHEME) > $@
ghash-sparcv9.s:	asm/ghash-sparcv9.pl
	$(PERL) asm/ghash-sparcv9.pl $@ $(CFLAGS_crypto_modes)
ghash-alpha.s:	asm/ghash-alpha.pl
	(preproc=/tmp/$$$$.$@; trap "rm $$preproc" INT; \
	$(PERL) asm/ghash-alpha.pl > $$preproc && \
	$(CC) -E $$preproc > $@ && rm $$preproc)
ghash-parisc.s:	asm/ghash-parisc.pl
	$(PERL) asm/ghash-parisc.pl $(PERLASM_SCHEME) $@
ghashv8-armx.S:	asm/ghashv8-armx.pl
	$(PERL) asm/ghashv8-armx.pl $(PERLASM_SCHEME) $@
ghashp8-ppc.s:	asm/ghashp8-ppc.pl
	$(PERL) asm/ghashp8-ppc.pl $(PERLASM_SCHEME) $@

# GNU make "catch all"
ghash-%.S:	asm/ghash-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

ghash-armv4.o:	ghash-armv4.S
ghashv8-armx.o:	ghashv8-armx.S

files: files_crypto_modes
files_crypto_modes:
	$(PERL) $(TOP_crypto_modes)/util/files.pl TOP=$(TOP_crypto_modes) Makefile >> $(TOP_crypto_modes)/MINFO

links: links_crypto_modes
links_crypto_modes:
	@$(PERL) $(TOP_crypto_modes)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_modes)
	@$(PERL) $(TOP_crypto_modes)/util/mklink.pl ../../test $(TEST_crypto_modes)
	@$(PERL) $(TOP_crypto_modes)/util/mklink.pl ../../apps $(APPS_crypto_modes)

install: install_crypto_modes
install_crypto_modes:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_modes)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_modes
tags_crypto_modes:
	ctags $(SRC_crypto_modes)

tests: tests_crypto_modes
tests_crypto_modes:

lint: lint_crypto_modes
lint_crypto_modes:
	lint -DLINT $(INCLUDES_crypto_modes) $(SRC_crypto_modes)>fluff

dclean: dclean_crypto_modes
dclean_crypto_modes:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_modes
clean_crypto_modes:
	rm -f *.s *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_modes) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_modes) -o $@ $<
