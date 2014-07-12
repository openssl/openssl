#
# OpenSSL/crypto/txt_db/Makefile
#

DIR=	txt_db
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=txt_db.c
LIBOBJ=txt_db.o

SRC= $(LIBSRC)

EXHEADER= txt_db.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_txt_db
top_crypto_txt_db:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_txt_db
all_crypto_txt_db:	lib

lib: lib_crypto_txt_db
lib_crypto_txt_db:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_txt_db
files_crypto_txt_db:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_txt_db
links_crypto_txt_db:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_txt_db
install_crypto_txt_db:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_txt_db
tags_crypto_txt_db:
	ctags $(SRC)

tests: tests_crypto_txt_db
tests_crypto_txt_db:

lint: lint_crypto_txt_db
lint_crypto_txt_db:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_txt_db
dclean_crypto_txt_db:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_txt_db
clean_crypto_txt_db:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

