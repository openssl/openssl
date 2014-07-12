#
# OpenSSL/crypto/rc4/Makefile
#

DIR=	rc4
CPP=    $(CC) -E
INCLUDES=


CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=rc4test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc4_skey.c rc4_enc.c
LIBOBJ=$(RC4_ENC)

SRC= $(LIBSRC)

EXHEADER= rc4.h
HEADER=	$(EXHEADER) rc4_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_rc4
top_crypto_rc4:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_rc4
all_crypto_rc4:	lib

lib: lib_crypto_rc4
lib_crypto_rc4:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

rc4-586.s:	asm/rc4-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/rc4-586.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

rc4-x86_64.s: asm/rc4-x86_64.pl
	$(PERL) asm/rc4-x86_64.pl $(PERLASM_SCHEME) > $@
rc4-md5-x86_64.s:	asm/rc4-md5-x86_64.pl
	$(PERL) asm/rc4-md5-x86_64.pl $(PERLASM_SCHEME) > $@

rc4-ia64.S: asm/rc4-ia64.pl
	$(PERL) asm/rc4-ia64.pl $(CFLAGS) > $@

rc4-parisc.s:	asm/rc4-parisc.pl
	$(PERL) asm/rc4-parisc.pl $(PERLASM_SCHEME) $@

rc4-ia64.s: rc4-ia64.S
	@case `awk '/^#define RC4_INT/{print$$NF}' $(TOP)/include/openssl/opensslconf.h` in \
	int)	set -x; $(CC) $(CFLAGS) -DSZ=4 -E rc4-ia64.S > $@ ;; \
	char)	set -x; $(CC) $(CFLAGS) -DSZ=1 -E rc4-ia64.S > $@ ;; \
	*)	exit 1 ;; \
	esac

# GNU make "catch all"
rc4-%.s:	asm/rc4-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

files: files_crypto_rc4
files_crypto_rc4:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_rc4
links_crypto_rc4:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_rc4
install_crypto_rc4:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc4
tags_crypto_rc4:
	ctags $(SRC)

tests: tests_crypto_rc4
tests_crypto_rc4:

lint: lint_crypto_rc4
lint_crypto_rc4:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_rc4
dclean_crypto_rc4:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_rc4
clean_crypto_rc4:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

