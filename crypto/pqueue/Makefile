#
# OpenSSL/crypto/pqueue/Makefile
#

DIR_crypto_pqueue=	pqueue
INCLUDES_crypto_pqueue=

CFLAGS_crypto_pqueue= $(INCLUDES_crypto_pqueue) $(CFLAG)

GENERAL_crypto_pqueue=Makefile
TEST_crypto_pqueue=
APPS_crypto_pqueue=

LIB_crypto_pqueue=$(TOP_crypto_pqueue)/libcrypto.a
LIBSRC_crypto_pqueue=pqueue.c
LIBOBJ_crypto_pqueue=pqueue.o

SRC_crypto_pqueue= $(LIBSRC_crypto_pqueue)

EXHEADER_crypto_pqueue= pqueue.h
HEADER_crypto_pqueue=	$(EXHEADER_crypto_pqueue)

ALL_crypto_pqueue=    $(GENERAL_crypto_pqueue) $(SRC_crypto_pqueue) $(HEADER_crypto_pqueue)

top: top_crypto_pqueue
top_crypto_pqueue:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_pqueue) sub_all)

all: all_crypto_pqueue
all_crypto_pqueue:	lib

lib:	$(LIBOBJ_crypto_pqueue)
	$(ARX) $(LIB_crypto_pqueue) $(LIBOBJ_crypto_pqueue)
	$(RANLIB) $(LIB_crypto_pqueue) || echo Never mind.
	@touch lib

files: files_crypto_pqueue
files_crypto_pqueue:
	$(PERL) $(TOP_crypto_pqueue)/util/files.pl TOP=$(TOP_crypto_pqueue) Makefile >> $(TOP_crypto_pqueue)/MINFO

links: links_crypto_pqueue
links_crypto_pqueue:
	@$(PERL) $(TOP_crypto_pqueue)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_pqueue)
	@$(PERL) $(TOP_crypto_pqueue)/util/mklink.pl ../../test $(TEST_crypto_pqueue)
	@$(PERL) $(TOP_crypto_pqueue)/util/mklink.pl ../../apps $(APPS_crypto_pqueue)

install: install_crypto_pqueue
install_crypto_pqueue:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_pqueue)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pqueue
tags_crypto_pqueue:
	ctags $(SRC_crypto_pqueue)

tests: tests_crypto_pqueue
tests_crypto_pqueue:

lint: lint_crypto_pqueue
lint_crypto_pqueue:
	lint -DLINT $(INCLUDES_crypto_pqueue) $(SRC_crypto_pqueue)>fluff

dclean: dclean_crypto_pqueue
dclean_crypto_pqueue:

clean: clean_crypto_pqueue
clean_crypto_pqueue:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_pqueue) $(CPPFLAGS) -c -o $@ $<
