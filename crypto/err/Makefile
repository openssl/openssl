#
# OpenSSL/crypto/err/Makefile
#

DIR_crypto_err=	err
INCLUDES_crypto_err= -I.. -I$(TOP_crypto_err) -I../../include

CFLAGS_crypto_err= $(INCLUDES_crypto_err) $(CFLAG)

GENERAL_crypto_err=Makefile
TEST_crypto_err=
APPS_crypto_err=

LIB_crypto_err=$(TOP_crypto_err)/libcrypto.a
LIBSRC_crypto_err=err.c err_all.c err_prn.c
LIBOBJ_crypto_err=err.o err_all.o err_prn.o

SRC_crypto_err= $(LIBSRC_crypto_err)

EXHEADER_crypto_err= err.h
HEADER_crypto_err=	$(EXHEADER_crypto_err)

ALL_crypto_err=    $(GENERAL_crypto_err) $(SRC_crypto_err) $(HEADER_crypto_err)

top: top_crypto_err
top_crypto_err:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_err) sub_all)

all: all_crypto_err
all_crypto_err:	lib

lib: lib_crypto_err
lib_crypto_err:	$(LIBOBJ_crypto_err)
	$(ARX) $(LIB_crypto_err) $(LIBOBJ_crypto_err)
	$(RANLIB) $(LIB_crypto_err) || echo Never mind.
	@touch lib

files: files_crypto_err
files_crypto_err:
	$(PERL) $(TOP_crypto_err)/util/files.pl TOP=$(TOP_crypto_err) Makefile >> $(TOP_crypto_err)/MINFO

links: links_crypto_err
links_crypto_err:
	@$(PERL) $(TOP_crypto_err)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_err)
	@$(PERL) $(TOP_crypto_err)/util/mklink.pl ../../test $(TEST_crypto_err)
	@$(PERL) $(TOP_crypto_err)/util/mklink.pl ../../apps $(APPS_crypto_err)

install: install_crypto_err
install_crypto_err:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_err)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_err
tags_crypto_err:
	ctags $(SRC_crypto_err)

tests: tests_crypto_err
tests_crypto_err:

lint: lint_crypto_err
lint_crypto_err:
	lint -DLINT $(INCLUDES_crypto_err) $(SRC_crypto_err)>fluff

dclean: dclean_crypto_err
dclean_crypto_err:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_err
clean_crypto_err:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_err) $(CPPFLAGS) -c -o $@ $<
