#
# OpenSSL/crypto/store/Makefile
#

DIR=	store
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
#TEST= storetest.c
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= str_err.c str_lib.c str_meth.c str_mem.c
LIBOBJ= str_err.o str_lib.o str_meth.o str_mem.o

SRC= $(LIBSRC)

#EXHEADER= store.h str_compat.h
EXHEADER= store.h
HEADER=	$(EXHEADER) str_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_store
top_crypto_store:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_store
all_crypto_store:	lib

lib: lib_crypto_store
lib_crypto_store:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_store
files_crypto_store:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_store
links_crypto_store:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_store
install_crypto_store:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_store
tags_crypto_store:
	ctags $(SRC)

tests: tests_crypto_store
tests_crypto_store:

lint: lint_crypto_store
lint_crypto_store:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_store
dclean_crypto_store:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_store
clean_crypto_store:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

