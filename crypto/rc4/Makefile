#
# OpenSSL/crypto/rc4/Makefile
#

CPP_crypto_rc4=    $(CC) -E
INCLUDES_crypto_rc4=


CFLAGS_crypto_rc4= $(INCLUDES_crypto_rc4) $(CFLAG)
ASFLAGS_crypto_rc4= $(INCLUDES_crypto_rc4) $(ASFLAG)
AFLAGS_crypto_rc4= $(ASFLAGS_crypto_rc4)

GENERAL_crypto_rc4=crypto/rc4/Makefile
TEST_crypto_rc4=crypto/rc4/rc4test.c
APPS_crypto_rc4=

LIB_crypto_rc4=libcrypto.a
LIBSRC_crypto_rc4=crypto/rc4/rc4_skey.c crypto/rc4/rc4_enc.c
LIBOBJ_crypto_rc4=$(RC4_ENC)

SRC_crypto_rc4= $(LIBSRC_crypto_rc4)

EXHEADER_crypto_rc4= crypto/rc4/rc4.h
HEADER_crypto_rc4=	$(EXHEADER_crypto_rc4) crypto/rc4/rc4_locl.h

ALL_crypto_rc4=    $(GENERAL_crypto_rc4) $(SRC_crypto_rc4) $(HEADER_crypto_rc4)


all: all_crypto_rc4
all_crypto_rc4:	crypto/rc4/lib

crypto/rc4/lib:	$(LIBOBJ_crypto_rc4)
	$(ARX) $(LIB_crypto_rc4) $(LIBOBJ_crypto_rc4)
	$(RANLIB) $(LIB_crypto_rc4) || echo Never mind.
	@touch crypto/rc4/lib

crypto/rc4/rc4-586.s:	crypto/rc4/asm/rc4-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/rc4/asm/rc4-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_rc4) $(PROCESSOR) > $@

crypto/rc4/rc4-x86_64.s: crypto/rc4/asm/rc4-x86_64.pl
	$(PERL) crypto/rc4/asm/rc4-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/rc4/rc4-md5-x86_64.s:	crypto/rc4/asm/rc4-md5-x86_64.pl
	$(PERL) crypto/rc4/asm/rc4-md5-x86_64.pl $(PERLASM_SCHEME) > $@

crypto/rc4/rc4-ia64.S: crypto/rc4/asm/rc4-ia64.pl
	$(PERL) crypto/rc4/asm/rc4-ia64.pl $(CFLAGS_crypto_rc4) > $@

crypto/rc4/rc4-parisc.s:	crypto/rc4/asm/rc4-parisc.pl
	$(PERL) crypto/rc4/asm/rc4-parisc.pl $(PERLASM_SCHEME) $@

crypto/rc4/rc4-ia64.s: crypto/rc4/rc4-ia64.S
	@case `awk '/^#define RC4_INT/{print$$NF}' include/openssl/opensslconf.h` in \
	int)	set -x; $(CC) $(CFLAGS_crypto_rc4) -DSZ=4 -E crypto/rc4/rc4-ia64.S > $@ ;; \
	char)	set -x; $(CC) $(CFLAGS_crypto_rc4) -DSZ=1 -E crypto/rc4/rc4-ia64.S > $@ ;; \
	*)	exit 1 ;; \
	esac

# GNU make "catch all"
crypto/rc4/rc4-%.s:	crypto/rc4/asm/rc4-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

files: files_crypto_rc4
files_crypto_rc4:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_rc4
links_crypto_rc4:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_rc4)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_rc4)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_rc4)

install: install_crypto_rc4
install_crypto_rc4:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_rc4)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_rc4
tags_crypto_rc4:
	ctags $(SRC_crypto_rc4)

tests: tests_crypto_rc4
tests_crypto_rc4:

lint: lint_crypto_rc4
lint_crypto_rc4:
	lint -DLINT $(INCLUDES_crypto_rc4) $(SRC_crypto_rc4)>crypto/rc4/fluff

dclean: dclean_crypto_rc4
dclean_crypto_rc4:

clean: clean_crypto_rc4
clean_crypto_rc4:
	rm -f crypto/rc4/*.s crypto/rc4/*.o crypto/rc4/*.d crypto/rc4/*.obj crypto/rc4/lib crypto/rc4/tags crypto/rc4/core crypto/rc4/.pure crypto/rc4/.nfs* crypto/rc4/*.old crypto/rc4/*.bak crypto/rc4/fluff

.S.s:
	$(CPP_crypto_rc4) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_rc4) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_rc4) -o $@ $<
