#
# OpenSSL/crypto/pkcs7/Makefile
#


 
CFLAGS_crypto_pkcs7= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_pkcs7=crypto/pkcs7/Makefile crypto/pkcs7/README
TEST_crypto_pkcs7=
APPS_crypto_pkcs7=

LIB_crypto_pkcs7=libcrypto.a
LIBSRC_crypto_pkcs7=	crypto/pkcs7/pk7_asn1.c crypto/pkcs7/pk7_lib.c crypto/pkcs7/pkcs7err.c crypto/pkcs7/pk7_doit.c crypto/pkcs7/pk7_smime.c crypto/pkcs7/pk7_attr.c \
	crypto/pkcs7/pk7_mime.c crypto/pkcs7/bio_pk7.c
LIBOBJ_crypto_pkcs7= crypto/pkcs7/pk7_asn1.o crypto/pkcs7/pk7_lib.o crypto/pkcs7/pkcs7err.o crypto/pkcs7/pk7_doit.o crypto/pkcs7/pk7_smime.o crypto/pkcs7/pk7_attr.o \
	crypto/pkcs7/pk7_mime.o crypto/pkcs7/bio_pk7.o

SRC_crypto_pkcs7= $(LIBSRC_crypto_pkcs7)

EXHEADER_crypto_pkcs7=  crypto/pkcs7/pkcs7.h
HEADER_crypto_pkcs7=	$(EXHEADER_crypto_pkcs7)

ALL_crypto_pkcs7=    $(GENERAL_crypto_pkcs7) $(SRC_crypto_pkcs7) $(HEADER_crypto_pkcs7)

all: all_crypto_pkcs7
all_crypto_pkcs7:	crypto/pkcs7/lib

crypto/pkcs7/lib:	$(LIBOBJ_crypto_pkcs7)
	$(ARX) $(LIB_crypto_pkcs7) $(LIBOBJ_crypto_pkcs7)
	$(RANLIB) $(LIB_crypto_pkcs7) || echo Never mind.
	@touch crypto/pkcs7/lib

files: files_crypto_pkcs7
files_crypto_pkcs7:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_pkcs7
links_crypto_pkcs7:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_pkcs7)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_pkcs7)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_pkcs7)

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
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_pkcs7)>crypto/pkcs7/fluff

dclean: dclean_crypto_pkcs7
dclean_crypto_pkcs7:

clean: clean_crypto_pkcs7
clean_crypto_pkcs7:
	rm -f crypto/pkcs7/*.o crypto/pkcs7/*.d crypto/pkcs7/*.obj crypto/pkcs7/lib crypto/pkcs7/tags crypto/pkcs7/core crypto/pkcs7/.pure crypto/pkcs7/.nfs* crypto/pkcs7/*.old crypto/pkcs7/*.bak crypto/pkcs7/fluff crypto/pkcs7/enc crypto/pkcs7/dec crypto/pkcs7/sign crypto/pkcs7/verify

