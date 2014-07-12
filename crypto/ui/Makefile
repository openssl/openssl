#
# OpenSSL/crypto/ui/Makefile
#

DIR_crypto_ui=	ui
INCLUDES_crypto_ui= -I.. -I$(TOP_crypto_ui) -I../../include

CFLAGS_crypto_ui= $(INCLUDES_crypto_ui) $(CFLAG)

GENERAL_crypto_ui=Makefile
#TEST= uitest.c
TEST_crypto_ui=
APPS_crypto_ui=

COMPATSRC= ui_compat.c
COMPATOBJ= ui_compat.o

LIB_crypto_ui=$(TOP_crypto_ui)/libcrypto.a
LIBSRC_crypto_ui= ui_err.c ui_lib.c ui_openssl.c ui_util.c $(COMPATSRC)
LIBOBJ_crypto_ui= ui_err.o ui_lib.o ui_openssl.o ui_util.o $(COMPATOBJ)

SRC_crypto_ui= $(LIBSRC_crypto_ui)

EXHEADER_crypto_ui= ui.h ui_compat.h
HEADER_crypto_ui=	$(EXHEADER_crypto_ui) ui_locl.h

ALL_crypto_ui=    $(GENERAL_crypto_ui) $(SRC_crypto_ui) $(HEADER_crypto_ui)

top: top_crypto_ui
top_crypto_ui:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_ui) sub_all)

all: all_crypto_ui
all_crypto_ui:	lib

lib: lib_crypto_ui
lib_crypto_ui:	$(LIBOBJ_crypto_ui)
	$(ARX) $(LIB_crypto_ui) $(LIBOBJ_crypto_ui)
	$(RANLIB) $(LIB_crypto_ui) || echo Never mind.
	@touch lib

files: files_crypto_ui
files_crypto_ui:
	$(PERL) $(TOP_crypto_ui)/util/files.pl TOP=$(TOP_crypto_ui) Makefile >> $(TOP_crypto_ui)/MINFO

links: links_crypto_ui
links_crypto_ui:
	@$(PERL) $(TOP_crypto_ui)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ui)
	@$(PERL) $(TOP_crypto_ui)/util/mklink.pl ../../test $(TEST_crypto_ui)
	@$(PERL) $(TOP_crypto_ui)/util/mklink.pl ../../apps $(APPS_crypto_ui)

install: install_crypto_ui
install_crypto_ui:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ui)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ui
tags_crypto_ui:
	ctags $(SRC_crypto_ui)

tests: tests_crypto_ui
tests_crypto_ui:

lint: lint_crypto_ui
lint_crypto_ui:
	lint -DLINT $(INCLUDES_crypto_ui) $(SRC_crypto_ui)>fluff

dclean: dclean_crypto_ui
dclean_crypto_ui:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_ui
clean_crypto_ui:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_ui) $(CPPFLAGS) -c -o $@ $<
