DIR_crypto_srp=	srp
INCLUDES_crypto_srp= -I.. -I$(TOP_crypto_srp) -I../../include

CFLAGS_crypto_srp= $(INCLUDES_crypto_srp) $(CFLAG)

GENERAL_crypto_srp=Makefile
TEST_crypto_srp=srptest.c
APPS_crypto_srp=

LIB_crypto_srp=$(TOP_crypto_srp)/libcrypto.a
LIBSRC_crypto_srp=srp_lib.c srp_vfy.c
LIBOBJ_crypto_srp=srp_lib.o srp_vfy.o

SRC_crypto_srp= $(LIBSRC_crypto_srp)

EXHEADER_crypto_srp= srp.h
HEADER_crypto_srp=	$(EXHEADER_crypto_srp)

top: top_crypto_srp
top_crypto_srp:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_srp) sub_all)

all: all_crypto_srp
all_crypto_srp:	lib

lib: lib_crypto_srp
lib_crypto_srp:	$(LIBOBJ_crypto_srp)
	$(AR) $(LIB_crypto_srp) $(LIBOBJ_crypto_srp)
	$(RANLIB) $(LIB_crypto_srp) || echo Never mind.
	@touch lib

files: files_crypto_srp
files_crypto_srp:
	$(PERL) $(TOP_crypto_srp)/util/files.pl TOP=$(TOP_crypto_srp) Makefile >> $(TOP_crypto_srp)/MINFO

links: links_crypto_srp
links_crypto_srp:
	@$(PERL) $(TOP_crypto_srp)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_srp)
	@$(PERL) $(TOP_crypto_srp)/util/mklink.pl ../../test $(TEST_crypto_srp)
	@$(PERL) $(TOP_crypto_srp)/util/mklink.pl ../../apps $(APPS_crypto_srp)

install: install_crypto_srp
install_crypto_srp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_srp)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_srp
tags_crypto_srp:
	ctags $(SRC_crypto_srp)

tests: tests_crypto_srp
tests_crypto_srp:

lint: lint_crypto_srp
lint_crypto_srp:
	lint -DLINT $(INCLUDES_crypto_srp) $(SRC_crypto_srp)>fluff

dclean: dclean_crypto_srp
dclean_crypto_srp:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_srp
clean_crypto_srp:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_srp) $(CPPFLAGS) -c -o $@ $<
