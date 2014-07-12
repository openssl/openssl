#
# OpenSSL/crypto/cast/Makefile
#

DIR_crypto_cast=	cast
CPP_crypto_cast=	$(CC) -E
INCLUDES_crypto_cast=


CFLAGS_crypto_cast= $(INCLUDES_crypto_cast) $(CFLAG)
ASFLAGS_crypto_cast= $(INCLUDES_crypto_cast) $(ASFLAG)
AFLAGS_crypto_cast= $(ASFLAGS_crypto_cast)

GENERAL_crypto_cast=Makefile
TEST_crypto_cast=casttest.c
APPS_crypto_cast=

LIB_crypto_cast=$(TOP_crypto_cast)/libcrypto.a
LIBSRC_crypto_cast=c_skey.c c_ecb.c c_enc.c c_cfb64.c c_ofb64.c 
LIBOBJ_crypto_cast=c_skey.o c_ecb.o $(CAST_ENC) c_cfb64.o c_ofb64.o

SRC_crypto_cast= $(LIBSRC_crypto_cast)

EXHEADER_crypto_cast= cast.h
HEADER_crypto_cast=	cast_s.h cast_lcl.h $(EXHEADER_crypto_cast)

ALL_crypto_cast=    $(GENERAL_crypto_cast) $(SRC_crypto_cast) $(HEADER_crypto_cast)

top: top_crypto_cast
top_crypto_cast:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_cast) sub_all)

all: all_crypto_cast
all_crypto_cast:	lib

lib: lib_crypto_cast
lib_crypto_cast:	$(LIBOBJ_crypto_cast)
	$(ARX) $(LIB_crypto_cast) $(LIBOBJ_crypto_cast)
	$(RANLIB) $(LIB_crypto_cast) || echo Never mind.
	@touch lib

cast-586.s:	asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL)	asm/cast-586.pl $(PERLASM_SCHEME) $(CLAGS) $(PROCESSOR) > $@

files: files_crypto_cast
files_crypto_cast:
	$(PERL) $(TOP_crypto_cast)/util/files.pl TOP=$(TOP_crypto_cast) Makefile >> $(TOP_crypto_cast)/MINFO

links: links_crypto_cast
links_crypto_cast:
	@$(PERL) $(TOP_crypto_cast)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_cast)
	@$(PERL) $(TOP_crypto_cast)/util/mklink.pl ../../test $(TEST_crypto_cast)
	@$(PERL) $(TOP_crypto_cast)/util/mklink.pl ../../apps $(APPS_crypto_cast)

install: install_crypto_cast
install_crypto_cast:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_cast)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cast
tags_crypto_cast:
	ctags $(SRC_crypto_cast)

tests: tests_crypto_cast
tests_crypto_cast:

lint: lint_crypto_cast
lint_crypto_cast:
	lint -DLINT $(INCLUDES_crypto_cast) $(SRC_crypto_cast)>fluff

dclean: dclean_crypto_cast
dclean_crypto_cast:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_cast
clean_crypto_cast:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_cast) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_cast) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_cast) -o $@ $<
