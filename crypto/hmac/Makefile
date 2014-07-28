#
# OpenSSL/crypto/md/Makefile
#

DIR_crypto_hmac=	hmac
INCLUDES_crypto_hmac=

CFLAGS_crypto_hmac= $(INCLUDES_crypto_hmac) $(CFLAG)

GENERAL_crypto_hmac=Makefile
TEST_crypto_hmac=hmactest.c
APPS_crypto_hmac=

LIB_crypto_hmac=$(TOP_crypto_hmac)/libcrypto.a
LIBSRC_crypto_hmac=hmac.c hm_ameth.c hm_pmeth.c
LIBOBJ_crypto_hmac=hmac.o hm_ameth.o hm_pmeth.o

SRC_crypto_hmac= $(LIBSRC_crypto_hmac)

EXHEADER_crypto_hmac= hmac.h
HEADER_crypto_hmac=	$(EXHEADER_crypto_hmac)

ALL_crypto_hmac=    $(GENERAL_crypto_hmac) $(SRC_crypto_hmac) $(HEADER_crypto_hmac)

top: top_crypto_hmac
top_crypto_hmac:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_hmac) sub_all)

all: all_crypto_hmac
all_crypto_hmac:	lib

lib:	$(LIBOBJ_crypto_hmac)
	$(ARX) $(LIB_crypto_hmac) $(LIBOBJ_crypto_hmac)
	$(RANLIB) $(LIB_crypto_hmac) || echo Never mind.
	@touch lib

files: files_crypto_hmac
files_crypto_hmac:
	$(PERL) $(TOP_crypto_hmac)/util/files.pl TOP=$(TOP_crypto_hmac) Makefile >> $(TOP_crypto_hmac)/MINFO

links: links_crypto_hmac
links_crypto_hmac:
	@$(PERL) $(TOP_crypto_hmac)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_hmac)
	@$(PERL) $(TOP_crypto_hmac)/util/mklink.pl ../../test $(TEST_crypto_hmac)
	@$(PERL) $(TOP_crypto_hmac)/util/mklink.pl ../../apps $(APPS_crypto_hmac)

install: install_crypto_hmac
install_crypto_hmac:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_hmac)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_hmac
tags_crypto_hmac:
	ctags $(SRC_crypto_hmac)

tests: tests_crypto_hmac
tests_crypto_hmac:

lint: lint_crypto_hmac
lint_crypto_hmac:
	lint -DLINT $(INCLUDES_crypto_hmac) $(SRC_crypto_hmac)>fluff

dclean: dclean_crypto_hmac
dclean_crypto_hmac:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_hmac
clean_crypto_hmac:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_hmac) $(CPPFLAGS) -c -o $@ $<
