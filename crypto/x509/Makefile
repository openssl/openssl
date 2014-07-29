#
# OpenSSL/crypto/x509/Makefile
#

INCLUDES_crypto_x509= -Icrypto -I. -Iinclude

CFLAGS_crypto_x509= $(INCLUDES_crypto_x509) $(CFLAG)

GENERAL_crypto_x509=crypto/x509/Makefile crypto/x509/README
TEST_crypto_x509=
APPS_crypto_x509=

LIB_crypto_x509=libcrypto.a
LIBSRC_crypto_x509=	crypto/x509/x509_def.c crypto/x509/x509_d2.c crypto/x509/x509_r2x.c crypto/x509/x509_cmp.c \
	crypto/x509/x509_obj.c crypto/x509/x509_req.c crypto/x509/x509spki.c crypto/x509/x509_vfy.c \
	crypto/x509/x509_set.c crypto/x509/x509cset.c crypto/x509/x509rset.c crypto/x509/x509_err.c \
	crypto/x509/x509name.c crypto/x509/x509_v3.c crypto/x509/x509_ext.c crypto/x509/x509_att.c \
	crypto/x509/x509type.c crypto/x509/x509_lu.c crypto/x509/x_all.c crypto/x509/x509_txt.c \
	crypto/x509/x509_trs.c crypto/x509/by_file.c crypto/x509/by_dir.c crypto/x509/x509_vpm.c
LIBOBJ_crypto_x509= crypto/x509/x509_def.o crypto/x509/x509_d2.o crypto/x509/x509_r2x.o crypto/x509/x509_cmp.o \
	crypto/x509/x509_obj.o crypto/x509/x509_req.o crypto/x509/x509spki.o crypto/x509/x509_vfy.o \
	crypto/x509/x509_set.o crypto/x509/x509cset.o crypto/x509/x509rset.o crypto/x509/x509_err.o \
	crypto/x509/x509name.o crypto/x509/x509_v3.o crypto/x509/x509_ext.o crypto/x509/x509_att.o \
	crypto/x509/x509type.o crypto/x509/x509_lu.o crypto/x509/x_all.o crypto/x509/x509_txt.o \
	crypto/x509/x509_trs.o crypto/x509/by_file.o crypto/x509/by_dir.o crypto/x509/x509_vpm.o

SRC_crypto_x509= $(LIBSRC_crypto_x509)

EXHEADER_crypto_x509= crypto/x509/x509.h crypto/x509/x509_vfy.h
HEADER_crypto_x509=	$(EXHEADER_crypto_x509) crypto/x509/x509_lcl.h

ALL_crypto_x509=    $(GENERAL_crypto_x509) $(SRC_crypto_x509) $(HEADER_crypto_x509)


all: all_crypto_x509
all_crypto_x509:	crypto/x509/lib

crypto/x509/lib:	$(LIBOBJ_crypto_x509)
	$(ARX) $(LIB_crypto_x509) $(LIBOBJ_crypto_x509)
	$(RANLIB) $(LIB_crypto_x509) || echo Never mind.
	@touch crypto/x509/lib

files: files_crypto_x509
files_crypto_x509:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_x509
links_crypto_x509:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_x509)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_x509)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_x509)

install: install_crypto_x509
install_crypto_x509:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_x509)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_x509
tags_crypto_x509:
	ctags $(SRC_crypto_x509)

tests: tests_crypto_x509
tests_crypto_x509:

lint: lint_crypto_x509
lint_crypto_x509:
	lint -DLINT $(INCLUDES_crypto_x509) $(SRC_crypto_x509)>crypto/x509/fluff

dclean: dclean_crypto_x509
dclean_crypto_x509:

clean: clean_crypto_x509
clean_crypto_x509:
	rm -f crypto/x509/*.o crypto/x509/*.d crypto/x509/*.obj crypto/x509/lib crypto/x509/tags crypto/x509/core crypto/x509/.pure crypto/x509/.nfs* crypto/x509/*.old crypto/x509/*.bak crypto/x509/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_x509) $(CPPFLAGS) -c -o $@ $<
