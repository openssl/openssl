#
# OpenSSL/crypto/md/Makefile
#

DIR=	md2
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md2_dgst.c md2_one.c
LIBOBJ=md2_dgst.o md2_one.o

SRC= $(LIBSRC)

EXHEADER= md2.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_md2
top_crypto_md2:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_md2
all_crypto_md2:	lib

lib: lib_crypto_md2
lib_crypto_md2:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_md2
files_crypto_md2:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_md2
links_crypto_md2:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_md2
install_crypto_md2:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_md2
tags_crypto_md2:
	ctags $(SRC)

tests: tests_crypto_md2
tests_crypto_md2:

lint: lint_crypto_md2
lint_crypto_md2:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_md2
dclean_crypto_md2:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_md2
clean_crypto_md2:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

