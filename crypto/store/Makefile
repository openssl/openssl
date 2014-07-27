#
# OpenSSL/crypto/store/Makefile
#

DIR_crypto_store=	store
INCLUDES_crypto_store= -I.. -I$(TOP_crypto_store) -I../../include

CFLAGS_crypto_store= $(INCLUDES_crypto_store) $(CFLAG)

GENERAL_crypto_store=Makefile
#TEST= storetest.c
TEST_crypto_store=
APPS_crypto_store=

LIB_crypto_store=$(TOP_crypto_store)/libcrypto.a
LIBSRC_crypto_store= str_err.c str_lib.c str_meth.c str_mem.c
LIBOBJ_crypto_store= str_err.o str_lib.o str_meth.o str_mem.o

SRC_crypto_store= $(LIBSRC_crypto_store)

#EXHEADER= store.h str_compat.h
EXHEADER_crypto_store= store.h
HEADER_crypto_store=	$(EXHEADER_crypto_store) str_locl.h

ALL_crypto_store=    $(GENERAL_crypto_store) $(SRC_crypto_store) $(HEADER_crypto_store)

top: top_crypto_store
top_crypto_store:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_store) sub_all)

all: all_crypto_store
all_crypto_store:	lib

lib:	$(LIBOBJ_crypto_store)
	$(ARX) $(LIB_crypto_store) $(LIBOBJ_crypto_store)
	$(RANLIB) $(LIB_crypto_store) || echo Never mind.
	@touch lib

files: files_crypto_store
files_crypto_store:
	$(PERL) $(TOP_crypto_store)/util/files.pl TOP=$(TOP_crypto_store) Makefile >> $(TOP_crypto_store)/MINFO

links: links_crypto_store
links_crypto_store:
	@$(PERL) $(TOP_crypto_store)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_store)
	@$(PERL) $(TOP_crypto_store)/util/mklink.pl ../../test $(TEST_crypto_store)
	@$(PERL) $(TOP_crypto_store)/util/mklink.pl ../../apps $(APPS_crypto_store)

install: install_crypto_store
install_crypto_store:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_store)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_store
tags_crypto_store:
	ctags $(SRC_crypto_store)

tests: tests_crypto_store
tests_crypto_store:

lint: lint_crypto_store
lint_crypto_store:
	lint -DLINT $(INCLUDES_crypto_store) $(SRC_crypto_store)>fluff

dclean: dclean_crypto_store
dclean_crypto_store:

clean: clean_crypto_store
clean_crypto_store:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_store) $(CPPFLAGS) -c -o $@ $<
