#
# OpenSSL/crypto/pkcs12/Makefile
#

INCLUDES_crypto_pkcs12= -I.. -I$(TOP_crypto_pkcs12) -I../../include

CFLAGS_crypto_pkcs12= $(INCLUDES_crypto_pkcs12) $(CFLAG)

GENERAL_crypto_pkcs12=Makefile
TEST_crypto_pkcs12=
APPS_crypto_pkcs12=

LIB_crypto_pkcs12=$(TOP_crypto_pkcs12)/libcrypto.a
LIBSRC_crypto_pkcs12= p12_add.c p12_asn.c p12_attr.c p12_crpt.c p12_crt.c p12_decr.c \
	p12_init.c p12_key.c p12_kiss.c p12_mutl.c\
	p12_utl.c p12_npas.c pk12err.c p12_p8d.c p12_p8e.c
LIBOBJ_crypto_pkcs12= p12_add.o p12_asn.o p12_attr.o p12_crpt.o p12_crt.o p12_decr.o \
	p12_init.o p12_key.o p12_kiss.o p12_mutl.o\
	p12_utl.o p12_npas.o pk12err.o p12_p8d.o p12_p8e.o

SRC_crypto_pkcs12= $(LIBSRC_crypto_pkcs12)

EXHEADER_crypto_pkcs12=  pkcs12.h
HEADER_crypto_pkcs12=	$(EXHEADER_crypto_pkcs12)

ALL_crypto_pkcs12=    $(GENERAL_crypto_pkcs12) $(SRC_crypto_pkcs12) $(HEADER_crypto_pkcs12)


test: test_crypto_pkcs12
test_crypto_pkcs12:

all: all_crypto_pkcs12
all_crypto_pkcs12:	lib

lib:	$(LIBOBJ_crypto_pkcs12)
	$(ARX) $(LIB_crypto_pkcs12) $(LIBOBJ_crypto_pkcs12)
	$(RANLIB) $(LIB_crypto_pkcs12) || echo Never mind.
	@touch lib

files: files_crypto_pkcs12
files_crypto_pkcs12:
	$(PERL) $(TOP_crypto_pkcs12)/util/files.pl TOP=$(TOP_crypto_pkcs12) Makefile >> $(TOP_crypto_pkcs12)/MINFO

links: links_crypto_pkcs12
links_crypto_pkcs12:
	@$(PERL) $(TOP_crypto_pkcs12)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_pkcs12)
	@$(PERL) $(TOP_crypto_pkcs12)/util/mklink.pl ../../test $(TEST_crypto_pkcs12)
	@$(PERL) $(TOP_crypto_pkcs12)/util/mklink.pl ../../apps $(APPS_crypto_pkcs12)

install: install_crypto_pkcs12
install_crypto_pkcs12:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_pkcs12)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pkcs12
tags_crypto_pkcs12:
	ctags $(SRC_crypto_pkcs12)

tests: tests_crypto_pkcs12
tests_crypto_pkcs12:

lint: lint_crypto_pkcs12
lint_crypto_pkcs12:
	lint -DLINT $(INCLUDES_crypto_pkcs12) $(SRC_crypto_pkcs12)>fluff

dclean: dclean_crypto_pkcs12
dclean_crypto_pkcs12:

clean: clean_crypto_pkcs12
clean_crypto_pkcs12:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_pkcs12) $(CPPFLAGS) -c -o $@ $<
