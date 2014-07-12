#
# OpenSSL/crypto/pqueue/Makefile
#

DIR=	pqueue
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=pqueue.c
LIBOBJ=pqueue.o

SRC= $(LIBSRC)

EXHEADER= pqueue.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_pqueue
top_crypto_pqueue:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_pqueue
all_crypto_pqueue:	lib

lib: lib_crypto_pqueue
lib_crypto_pqueue:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_pqueue
files_crypto_pqueue:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_pqueue
links_crypto_pqueue:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_pqueue
install_crypto_pqueue:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pqueue
tags_crypto_pqueue:
	ctags $(SRC)

tests: tests_crypto_pqueue
tests_crypto_pqueue:

lint: lint_crypto_pqueue
lint_crypto_pqueue:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_pqueue
dclean_crypto_pqueue:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_pqueue
clean_crypto_pqueue:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

