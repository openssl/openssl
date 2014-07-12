#
# OpenSSL/crypto/blowfish/Makefile
#

DIR_crypto_bf=	bf
CPP_crypto_bf=	$(CC) -E
INCLUDES_crypto_bf=


CFLAGS_crypto_bf= $(INCLUDES_crypto_bf) $(CFLAG)
ASFLAGS_crypto_bf= $(INCLUDES_crypto_bf) $(ASFLAG)
AFLAGS_crypto_bf= $(ASFLAGS_crypto_bf)

GENERAL_crypto_bf=Makefile
TEST_crypto_bf=bftest.c
APPS_crypto_bf=

LIB_crypto_bf=$(TOP_crypto_bf)/libcrypto.a
LIBSRC_crypto_bf=bf_skey.c bf_ecb.c bf_enc.c bf_cfb64.c bf_ofb64.c 
LIBOBJ_crypto_bf=bf_skey.o bf_ecb.o $(BF_ENC) bf_cfb64.o bf_ofb64.o

SRC_crypto_bf= $(LIBSRC_crypto_bf)

EXHEADER_crypto_bf= blowfish.h
HEADER_crypto_bf=	bf_pi.h bf_locl.h $(EXHEADER_crypto_bf)

ALL_crypto_bf=    $(GENERAL_crypto_bf) $(SRC_crypto_bf) $(HEADER_crypto_bf)

top: top_crypto_bf
top_crypto_bf:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_bf) sub_all)

all: all_crypto_bf
all_crypto_bf:	lib

lib: lib_crypto_bf
lib_crypto_bf:	$(LIBOBJ_crypto_bf)
	$(ARX) $(LIB_crypto_bf) $(LIBOBJ_crypto_bf)
	$(RANLIB) $(LIB_crypto_bf) || echo Never mind.
	@touch lib

bf-586.s:	asm/bf-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/bf-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_bf) $(PROCESSOR) > $@

files: files_crypto_bf
files_crypto_bf:
	$(PERL) $(TOP_crypto_bf)/util/files.pl TOP=$(TOP_crypto_bf) Makefile >> $(TOP_crypto_bf)/MINFO

links: links_crypto_bf
links_crypto_bf:
	@$(PERL) $(TOP_crypto_bf)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_bf)
	@$(PERL) $(TOP_crypto_bf)/util/mklink.pl ../../test $(TEST_crypto_bf)
	@$(PERL) $(TOP_crypto_bf)/util/mklink.pl ../../apps $(APPS_crypto_bf)

# We need to use force because 'install' matches 'INSTALL' on case
# insensitive systems
FRC.install: FRC.install_crypto_bf
FRC.install_crypto_bf:
install: install_crypto_bf
install_crypto_bf: FRC.install
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_bf)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_bf
tags_crypto_bf:
	ctags $(SRC_crypto_bf)

tests: tests_crypto_bf
tests_crypto_bf:

lint: lint_crypto_bf
lint_crypto_bf:
	lint -DLINT $(INCLUDES_crypto_bf) $(SRC_crypto_bf)>fluff

dclean: dclean_crypto_bf
dclean_crypto_bf:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_bf
clean_crypto_bf:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.S.s:
	$(CPP_crypto_bf) $(CPPFLAGS) -o $@ $<
.c.o:
	$(CC) $(CFLAGS_crypto_bf) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_bf) -o $@ $<
