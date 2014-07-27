#
# OpenSSL/crypto/pem/Makefile
#

INCLUDES_crypto_pem= -I.. -I$(TOP_crypto_pem) -I../../include

CFLAGS_crypto_pem= $(INCLUDES_crypto_pem) $(CFLAG)

GENERAL_crypto_pem=Makefile
TEST_crypto_pem=
APPS_crypto_pem=

LIB_crypto_pem=$(TOP_crypto_pem)/libcrypto.a
LIBSRC_crypto_pem= pem_sign.c pem_seal.c pem_info.c pem_lib.c pem_all.c pem_err.c \
	pem_x509.c pem_xaux.c pem_oth.c pem_pk8.c pem_pkey.c pvkfmt.c

LIBOBJ_crypto_pem=	pem_sign.o pem_seal.o pem_info.o pem_lib.o pem_all.o pem_err.o \
	pem_x509.o pem_xaux.o pem_oth.o pem_pk8.o pem_pkey.o pvkfmt.o

SRC_crypto_pem= $(LIBSRC_crypto_pem)

EXHEADER_crypto_pem= pem.h pem2.h
HEADER_crypto_pem=	$(EXHEADER_crypto_pem)

ALL_crypto_pem=    $(GENERAL_crypto_pem) $(SRC_crypto_pem) $(HEADER_crypto_pem)


all: all_crypto_pem
all_crypto_pem:	lib

lib:	$(LIBOBJ_crypto_pem)
	$(ARX) $(LIB_crypto_pem) $(LIBOBJ_crypto_pem)
	$(RANLIB) $(LIB_crypto_pem) || echo Never mind.
	@touch lib

files: files_crypto_pem
files_crypto_pem:
	$(PERL) $(TOP_crypto_pem)/util/files.pl TOP=$(TOP_crypto_pem) Makefile >> $(TOP_crypto_pem)/MINFO

links: links_crypto_pem
links_crypto_pem: $(EXHEADER_crypto_pem)
	@$(PERL) $(TOP_crypto_pem)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_pem)
	@$(PERL) $(TOP_crypto_pem)/util/mklink.pl ../../test $(TEST_crypto_pem)
	@$(PERL) $(TOP_crypto_pem)/util/mklink.pl ../../apps $(APPS_crypto_pem)

install: install_crypto_pem
install_crypto_pem:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_pem)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_pem
tags_crypto_pem:
	ctags $(SRC_crypto_pem)

tests: tests_crypto_pem
tests_crypto_pem:

lint: lint_crypto_pem
lint_crypto_pem:
	lint -DLINT $(INCLUDES_crypto_pem) $(SRC_crypto_pem)>fluff

dclean: dclean_crypto_pem
dclean_crypto_pem:

clean: clean_crypto_pem
clean_crypto_pem:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_pem) $(CPPFLAGS) -c -o $@ $<
