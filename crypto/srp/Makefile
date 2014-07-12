DIR=	srp
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=srptest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=srp_lib.c srp_vfy.c
LIBOBJ=srp_lib.o srp_vfy.o

SRC= $(LIBSRC)

EXHEADER= srp.h
HEADER=	$(EXHEADER)

top: top_crypto_srp
top_crypto_srp:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_srp
all_crypto_srp:	lib

lib: lib_crypto_srp
lib_crypto_srp:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_srp
files_crypto_srp:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_srp
links_crypto_srp:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_srp
install_crypto_srp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_srp
tags_crypto_srp:
	ctags $(SRC)

tests: tests_crypto_srp
tests_crypto_srp:

lint: lint_crypto_srp
lint_crypto_srp:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_srp
dclean_crypto_srp:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_srp
clean_crypto_srp:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

