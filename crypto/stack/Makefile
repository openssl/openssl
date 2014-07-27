#
# OpenSSL/crypto/stack/Makefile
#

DIR_crypto_stack=	stack
INCLUDES_crypto_stack=

CFLAGS_crypto_stack= $(INCLUDES_crypto_stack) $(CFLAG)

GENERAL_crypto_stack=Makefile
TEST_crypto_stack=
APPS_crypto_stack=

LIB_crypto_stack=$(TOP_crypto_stack)/libcrypto.a
LIBSRC_crypto_stack=stack.c
LIBOBJ_crypto_stack=stack.o

SRC_crypto_stack= $(LIBSRC_crypto_stack)

EXHEADER_crypto_stack= stack.h safestack.h
HEADER_crypto_stack=	$(EXHEADER_crypto_stack)

ALL_crypto_stack=    $(GENERAL_crypto_stack) $(SRC_crypto_stack) $(HEADER_crypto_stack)

top: top_crypto_stack
top_crypto_stack:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_stack) sub_all)

all: all_crypto_stack
all_crypto_stack:	lib

lib:	$(LIBOBJ_crypto_stack)
	$(ARX) $(LIB_crypto_stack) $(LIBOBJ_crypto_stack)
	$(RANLIB) $(LIB_crypto_stack) || echo Never mind.
	@touch lib

files: files_crypto_stack
files_crypto_stack:
	$(PERL) $(TOP_crypto_stack)/util/files.pl TOP=$(TOP_crypto_stack) Makefile >> $(TOP_crypto_stack)/MINFO

links: links_crypto_stack
links_crypto_stack:
	@$(PERL) $(TOP_crypto_stack)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_stack)
	@$(PERL) $(TOP_crypto_stack)/util/mklink.pl ../../test $(TEST_crypto_stack)
	@$(PERL) $(TOP_crypto_stack)/util/mklink.pl ../../apps $(APPS_crypto_stack)

install: install_crypto_stack
install_crypto_stack:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_stack)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_stack
tags_crypto_stack:
	ctags $(SRC_crypto_stack)

tests: tests_crypto_stack
tests_crypto_stack:

lint: lint_crypto_stack
lint_crypto_stack:
	lint -DLINT $(INCLUDES_crypto_stack) $(SRC_crypto_stack)>fluff

dclean: dclean_crypto_stack
dclean_crypto_stack:

clean: clean_crypto_stack
clean_crypto_stack:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_stack) $(CPPFLAGS) -c -o $@ $<
