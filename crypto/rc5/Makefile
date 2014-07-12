#
# OpenSSL/crypto/rc5/Makefile
#

DIR_crypto_rc5=	rc5
CPP_crypto_rc5=	$(CC) -E
INCLUDES_crypto_rc5=


CFLAGS_crypto_rc5= $(INCLUDES_crypto_rc5) $(CFLAG)
ASFLAGS_crypto_rc5= $(INCLUDES_crypto_rc5) $(ASFLAG)
AFLAGS_crypto_rc5= $(ASFLAGS_crypto_rc5)

GENERAL_crypto_rc5=Makefile
TEST_crypto_rc5=rc5test.c
APPS_crypto_rc5=

LIB_crypto_rc5=$(TOP_crypto_rc5)/libcrypto.a
LIBSRC_crypto_rc5=rc5_skey.c rc5_ecb.c rc5_enc.c rc5cfb64.c rc5ofb64.c 
LIBOBJ_crypto_rc5=rc5_skey.o rc5_ecb.o $(RC5_ENC) rc5cfb64.o rc5ofb64.o

SRC_crypto_rc5= $(LIBSRC_crypto_rc5)

EXHEADER_crypto_rc5= rc5.h
HEADER_crypto_rc5=	rc5_locl.h $(EXHEADER_crypto_rc5)

ALL_crypto_rc5=    $(GENERAL_crypto_rc5) $(SRC_crypto_rc5) $(HEADER_crypto_rc5)

top: top_crypto_rc5
top_crypto_rc5:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_rc5) sub_all)

all: all_crypto_rc5
all_crypto_rc5:	lib

lib: lib_crypto_rc5
lib_crypto_rc5:	$(LIBOBJ_crypto_rc5)
	$(ARX) $(LIB_crypto_rc5) $(LIBOBJ_crypto_rc5)
	$(RANLIB) $(LIB_crypto_rc5) || echo Never mind.
	@touch lib

rc5-586.s: asm/rc5-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/rc5-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_rc5) > $@

files: files_crypto_rc5
files_crypto_rc5:
	$(PERL) $(TOP_crypto_rc5)/util/files.pl TOP=$(TOP_crypto_rc5) Makefile >> $(TOP_crypto_rc5)/MINFO

links: links_crypto_rc5
links_crypto_rc5:
	@$(PERL) $(TOP_crypto_rc5)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_rc5)
	@$(PERL) $(TOP_crypto_rc5)/util/mklink.pl ../../test $(TEST_crypto_rc5)
	@$(PERL) $(TOP_crypto_rc5)/util/mklink.pl ../../apps $(APPS_crypto_rc5)

install: install_crypto_rc5
install_crypto_rc5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rc5)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc5
tags_crypto_rc5:
	ctags $(SRC_crypto_rc5)

tests: tests_crypto_rc5
tests_crypto_rc5:

lint: lint_crypto_rc5
lint_crypto_rc5:
	lint -DLINT $(INCLUDES_crypto_rc5) $(SRC_crypto_rc5)>fluff

dclean: dclean_crypto_rc5
dclean_crypto_rc5:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_rc5
clean_crypto_rc5:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_rc5) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_rc5) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_rc5) -o $@ $<
