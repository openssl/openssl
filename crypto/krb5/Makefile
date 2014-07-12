#
# OpenSSL/krb5/Makefile
#

DIR_crypto_krb5=	krb5
INCLUDES_crypto_krb5= -I.. -I$(TOP_crypto_krb5) -I../../include

CFLAGS_crypto_krb5= $(INCLUDES_crypto_krb5) $(CFLAG)

GENERAL_crypto_krb5=Makefile README
TEST_crypto_krb5=
APPS_crypto_krb5=

LIB_crypto_krb5=$(TOP_crypto_krb5)/libcrypto.a
LIBSRC_crypto_krb5= krb5_asn.c

LIBOBJ_crypto_krb5= krb5_asn.o

SRC_crypto_krb5= $(LIBSRC_crypto_krb5)

EXHEADER_crypto_krb5= krb5_asn.h
HEADER_crypto_krb5=	$(EXHEADER_crypto_krb5)

ALL_crypto_krb5=    $(GENERAL_crypto_krb5) $(SRC_crypto_krb5) $(HEADER_crypto_krb5)

top: top_crypto_krb5
top_crypto_krb5:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_krb5) sub_all)

all: all_crypto_krb5
all_crypto_krb5:	lib

lib: lib_crypto_krb5
lib_crypto_krb5:	$(LIBOBJ_crypto_krb5)
	$(ARX) $(LIB_crypto_krb5) $(LIBOBJ_crypto_krb5)
	$(RANLIB) $(LIB_crypto_krb5) || echo Never mind.
	@touch lib

files: files_crypto_krb5
files_crypto_krb5:
	$(PERL) $(TOP_crypto_krb5)/util/files.pl TOP=$(TOP_crypto_krb5) Makefile >> $(TOP_crypto_krb5)/MINFO

links: links_crypto_krb5
links_crypto_krb5:
	@$(PERL) $(TOP_crypto_krb5)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_krb5)
	@$(PERL) $(TOP_crypto_krb5)/util/mklink.pl ../../test $(TEST_crypto_krb5)
	@$(PERL) $(TOP_crypto_krb5)/util/mklink.pl ../../apps $(APPS_crypto_krb5)

install: install_crypto_krb5
install_crypto_krb5:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_krb5)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_krb5
tags_crypto_krb5:
	ctags $(SRC_crypto_krb5)

tests: tests_crypto_krb5
tests_crypto_krb5:

lint: lint_crypto_krb5
lint_crypto_krb5:
	lint -DLINT $(INCLUDES_crypto_krb5) $(SRC_crypto_krb5)>fluff

dclean: dclean_crypto_krb5
dclean_crypto_krb5:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_krb5
clean_crypto_krb5:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_krb5) $(CPPFLAGS) -c -o $@ $<
