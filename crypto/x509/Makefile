#
# OpenSSL/crypto/x509/Makefile
#

DIR_crypto_x509=	x509
INCLUDES_crypto_x509= -I.. -I$(TOP_crypto_x509) -I../../include

CFLAGS_crypto_x509= $(INCLUDES_crypto_x509) $(CFLAG)

GENERAL_crypto_x509=Makefile README
TEST_crypto_x509=
APPS_crypto_x509=

LIB_crypto_x509=$(TOP_crypto_x509)/libcrypto.a
LIBSRC_crypto_x509=	x509_def.c x509_d2.c x509_r2x.c x509_cmp.c \
	x509_obj.c x509_req.c x509spki.c x509_vfy.c \
	x509_set.c x509cset.c x509rset.c x509_err.c \
	x509name.c x509_v3.c x509_ext.c x509_att.c \
	x509type.c x509_lu.c x_all.c x509_txt.c \
	x509_trs.c by_file.c by_dir.c x509_vpm.c
LIBOBJ_crypto_x509= x509_def.o x509_d2.o x509_r2x.o x509_cmp.o \
	x509_obj.o x509_req.o x509spki.o x509_vfy.o \
	x509_set.o x509cset.o x509rset.o x509_err.o \
	x509name.o x509_v3.o x509_ext.o x509_att.o \
	x509type.o x509_lu.o x_all.o x509_txt.o \
	x509_trs.o by_file.o by_dir.o x509_vpm.o

SRC_crypto_x509= $(LIBSRC_crypto_x509)

EXHEADER_crypto_x509= x509.h x509_vfy.h
HEADER_crypto_x509=	$(EXHEADER_crypto_x509) x509_lcl.h

ALL_crypto_x509=    $(GENERAL_crypto_x509) $(SRC_crypto_x509) $(HEADER_crypto_x509)

top: top_crypto_x509
top_crypto_x509:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_x509) sub_all)

all: all_crypto_x509
all_crypto_x509:	lib

lib:	$(LIBOBJ_crypto_x509)
	$(ARX) $(LIB_crypto_x509) $(LIBOBJ_crypto_x509)
	$(RANLIB) $(LIB_crypto_x509) || echo Never mind.
	@touch lib

files: files_crypto_x509
files_crypto_x509:
	$(PERL) $(TOP_crypto_x509)/util/files.pl TOP=$(TOP_crypto_x509) Makefile >> $(TOP_crypto_x509)/MINFO

links: links_crypto_x509
links_crypto_x509:
	@$(PERL) $(TOP_crypto_x509)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_x509)
	@$(PERL) $(TOP_crypto_x509)/util/mklink.pl ../../test $(TEST_crypto_x509)
	@$(PERL) $(TOP_crypto_x509)/util/mklink.pl ../../apps $(APPS_crypto_x509)

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
	lint -DLINT $(INCLUDES_crypto_x509) $(SRC_crypto_x509)>fluff

dclean: dclean_crypto_x509
dclean_crypto_x509:

clean: clean_crypto_x509
clean_crypto_x509:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_x509) $(CPPFLAGS) -c -o $@ $<
