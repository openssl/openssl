#
# OpenSSL/crypto/dso/Makefile
#

DIR_crypto_dso=	dso
INCLUDES_crypto_dso= -I.. -I$(TOP_crypto_dso) -I../../include

CFLAGS_crypto_dso= $(INCLUDES_crypto_dso) $(CFLAG)

GENERAL_crypto_dso=Makefile
TEST_crypto_dso=
APPS_crypto_dso=

LIB_crypto_dso=$(TOP_crypto_dso)/libcrypto.a
LIBSRC_crypto_dso= dso_dl.c dso_dlfcn.c dso_err.c dso_lib.c dso_null.c \
	dso_openssl.c dso_win32.c dso_vms.c dso_beos.c
LIBOBJ_crypto_dso= dso_dl.o dso_dlfcn.o dso_err.o dso_lib.o dso_null.o \
	dso_openssl.o dso_win32.o dso_vms.o dso_beos.o

SRC_crypto_dso= $(LIBSRC_crypto_dso)

EXHEADER_crypto_dso= dso.h
HEADER_crypto_dso=	$(EXHEADER_crypto_dso)

ALL_crypto_dso=    $(GENERAL_crypto_dso) $(SRC_crypto_dso) $(HEADER_crypto_dso)

top: top_crypto_dso
top_crypto_dso:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_dso) sub_all)

all: all_crypto_dso
all_crypto_dso:	lib

lib: lib_crypto_dso
lib_crypto_dso:	$(LIBOBJ_crypto_dso)
	$(ARX) $(LIB_crypto_dso) $(LIBOBJ_crypto_dso)
	$(RANLIB) $(LIB_crypto_dso) || echo Never mind.
	@touch lib

files: files_crypto_dso
files_crypto_dso:
	$(PERL) $(TOP_crypto_dso)/util/files.pl TOP=$(TOP_crypto_dso) Makefile >> $(TOP_crypto_dso)/MINFO

links: links_crypto_dso
links_crypto_dso:
	@$(PERL) $(TOP_crypto_dso)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_dso)
	@$(PERL) $(TOP_crypto_dso)/util/mklink.pl ../../test $(TEST_crypto_dso)
	@$(PERL) $(TOP_crypto_dso)/util/mklink.pl ../../apps $(APPS_crypto_dso)

install: install_crypto_dso
install_crypto_dso:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_dso)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_dso
tags_crypto_dso:
	ctags $(SRC_crypto_dso)

tests: tests_crypto_dso
tests_crypto_dso:

lint: lint_crypto_dso
lint_crypto_dso:
	lint -DLINT $(INCLUDES_crypto_dso) $(SRC_crypto_dso)>fluff

dclean: dclean_crypto_dso
dclean_crypto_dso:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_dso
clean_crypto_dso:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_dso) $(CPPFLAGS) -c -o $@ $<
