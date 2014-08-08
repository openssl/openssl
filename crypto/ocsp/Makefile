#
# OpenSSL/ocsp/Makefile
#

INCLUDES_crypto_ocsp= -Icrypto -I. -Iinclude

CFLAGS_crypto_ocsp= $(INCLUDES_crypto_ocsp) $(CFLAG)

GENERAL_crypto_ocsp=crypto/ocsp/Makefile crypto/ocsp/README
TEST_crypto_ocsp=
APPS_crypto_ocsp=

LIB_crypto_ocsp=libcrypto.a
LIBSRC_crypto_ocsp= crypto/ocsp/ocsp_asn.c crypto/ocsp/ocsp_ext.c crypto/ocsp/ocsp_ht.c crypto/ocsp/ocsp_lib.c crypto/ocsp/ocsp_cl.c \
	crypto/ocsp/ocsp_srv.c crypto/ocsp/ocsp_prn.c crypto/ocsp/ocsp_vfy.c crypto/ocsp/ocsp_err.c

LIBOBJ_crypto_ocsp= crypto/ocsp/ocsp_asn.o crypto/ocsp/ocsp_ext.o crypto/ocsp/ocsp_ht.o crypto/ocsp/ocsp_lib.o crypto/ocsp/ocsp_cl.o \
	crypto/ocsp/ocsp_srv.o crypto/ocsp/ocsp_prn.o crypto/ocsp/ocsp_vfy.o crypto/ocsp/ocsp_err.o

SRC_crypto_ocsp= $(LIBSRC_crypto_ocsp)

EXHEADER_crypto_ocsp= crypto/ocsp/ocsp.h
HEADER_crypto_ocsp=	$(EXHEADER_crypto_ocsp)

ALL_crypto_ocsp=    $(GENERAL_crypto_ocsp) $(SRC_crypto_ocsp) $(HEADER_crypto_ocsp)


all: all_crypto_ocsp
all_crypto_ocsp:	crypto/ocsp/lib

crypto/ocsp/lib:	$(LIBOBJ_crypto_ocsp)
	$(ARX) $(LIB_crypto_ocsp) $(LIBOBJ_crypto_ocsp)
	$(RANLIB) $(LIB_crypto_ocsp) || echo Never mind.
	@touch crypto/ocsp/lib

files: files_crypto_ocsp
files_crypto_ocsp:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ocsp
links_crypto_ocsp:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ocsp)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ocsp)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ocsp)

install: install_crypto_ocsp
install_crypto_ocsp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ocsp)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ocsp
tags_crypto_ocsp:
	ctags $(SRC_crypto_ocsp)

tests: tests_crypto_ocsp
tests_crypto_ocsp:

lint: lint_crypto_ocsp
lint_crypto_ocsp:
	lint -DLINT $(INCLUDES_crypto_ocsp) $(SRC_crypto_ocsp)>crypto/ocsp/fluff

dclean: dclean_crypto_ocsp
dclean_crypto_ocsp:

clean: clean_crypto_ocsp
clean_crypto_ocsp:
	rm -f crypto/ocsp/*.o crypto/ocsp/*.d crypto/ocsp/*.obj crypto/ocsp/lib crypto/ocsp/tags crypto/ocsp/core crypto/ocsp/.pure crypto/ocsp/.nfs* crypto/ocsp/*.old crypto/ocsp/*.bak crypto/ocsp/fluff

