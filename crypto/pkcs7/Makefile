#
# OpenSSL/crypto/pkcs7/Makefile
#

DIR_crypto_pkcs7=	pkcs7
INCLUDES_crypto_pkcs7= -I.. -I$(TOP_crypto_pkcs7) -I../../include

 
CFLAGS_crypto_pkcs7= $(INCLUDES_crypto_pkcs7) $(CFLAG)

GENERAL_crypto_pkcs7=Makefile README
TEST_crypto_pkcs7=
APPS_crypto_pkcs7=

LIB_crypto_pkcs7=$(TOP_crypto_pkcs7)/libcrypto.a
LIBSRC_crypto_pkcs7=	pk7_asn1.c pk7_lib.c pkcs7err.c pk7_doit.c pk7_smime.c pk7_attr.c \
	pk7_mime.c bio_pk7.c
LIBOBJ_crypto_pkcs7= pk7_asn1.o pk7_lib.o pkcs7err.o pk7_doit.o pk7_smime.o pk7_attr.o \
	pk7_mime.o bio_pk7.o

SRC_crypto_pkcs7= $(LIBSRC_crypto_pkcs7)

EXHEADER_crypto_pkcs7=  pkcs7.h
HEADER_crypto_pkcs7=	$(EXHEADER_crypto_pkcs7)

ALL_crypto_pkcs7=    $(GENERAL_crypto_pkcs7) $(SRC_crypto_pkcs7) $(HEADER_crypto_pkcs7)

top: top_crypto_pkcs7
top_crypto_pkcs7:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_pkcs7) sub_all)

test: test_crypto_pkcs7
test_crypto_pkcs7:

all: all_crypto_pkcs7
all_crypto_pkcs7:	lib

lib:	$(LIBOBJ_crypto_pkcs7)
	$(ARX) $(LIB_crypto_pkcs7) $(LIBOBJ_crypto_pkcs7)
	$(RANLIB) $(LIB_crypto_pkcs7) || echo Never mind.
	@touch lib

files: files_crypto_pkcs7
files_crypto_pkcs7:
	$(PERL) $(TOP_crypto_pkcs7)/util/files.pl TOP=$(TOP_crypto_pkcs7) Makefile >> $(TOP_crypto_pkcs7)/MINFO

links: links_crypto_pkcs7
links_crypto_pkcs7:
	@$(PERL) $(TOP_crypto_pkcs7)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_pkcs7)
	@$(PERL) $(TOP_crypto_pkcs7)/util/mklink.pl ../../test $(TEST_crypto_pkcs7)
	@$(PERL) $(TOP_crypto_pkcs7)/util/mklink.pl ../../apps $(APPS_crypto_pkcs7)

install: install_crypto_pkcs7
install_crypto_pkcs7:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_pkcs7)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pkcs7
tags_crypto_pkcs7:
	ctags $(SRC_crypto_pkcs7)

tests: tests_crypto_pkcs7
tests_crypto_pkcs7:

lint: lint_crypto_pkcs7
lint_crypto_pkcs7:
	lint -DLINT $(INCLUDES_crypto_pkcs7) $(SRC_crypto_pkcs7)>fluff

dclean: dclean_crypto_pkcs7
dclean_crypto_pkcs7:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_pkcs7
clean_crypto_pkcs7:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff enc dec sign verify

.c.o:
	$(CC) $(CFLAGS_crypto_pkcs7) $(CPPFLAGS) -c -o $@ $<
