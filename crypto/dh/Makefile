#
# OpenSSL/crypto/dh/Makefile
#

DIR=	dh
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= dhtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= dh_asn1.c dh_gen.c dh_key.c dh_lib.c dh_check.c dh_err.c dh_depr.c \
	dh_ameth.c dh_pmeth.c dh_prn.c dh_rfc5114.c dh_kdf.c
LIBOBJ= dh_asn1.o dh_gen.o dh_key.o dh_lib.o dh_check.o dh_err.o dh_depr.o \
	dh_ameth.o dh_pmeth.o dh_prn.o dh_rfc5114.o dh_kdf.o

SRC= $(LIBSRC)

EXHEADER= dh.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_dh
top_crypto_dh:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_dh
all_crypto_dh:	lib

lib: lib_crypto_dh
lib_crypto_dh:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_dh
files_crypto_dh:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_dh
links_crypto_dh:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_dh
install_crypto_dh:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_dh
tags_crypto_dh:
	ctags $(SRC)

tests: tests_crypto_dh
tests_crypto_dh:

lint: lint_crypto_dh
lint_crypto_dh:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_dh
dclean_crypto_dh:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_dh
clean_crypto_dh:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

