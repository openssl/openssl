#
# OpenSSL/crypto/cms/Makefile
#

DIR_crypto_cms=	cms
INCLUDES_crypto_cms= -I.. -I$(TOP_crypto_cms) -I../../include

CFLAGS_crypto_cms= $(INCLUDES_crypto_cms) $(CFLAG)

GENERAL_crypto_cms=Makefile
TEST_crypto_cms=
APPS_crypto_cms=

LIB_crypto_cms=$(TOP_crypto_cms)/libcrypto.a
LIBSRC_crypto_cms= cms_lib.c cms_asn1.c cms_att.c cms_io.c cms_smime.c cms_err.c \
	cms_sd.c cms_dd.c cms_cd.c cms_env.c cms_enc.c cms_ess.c \
	cms_pwri.c cms_kari.c
LIBOBJ_crypto_cms= cms_lib.o cms_asn1.o cms_att.o cms_io.o cms_smime.o cms_err.o \
	cms_sd.o cms_dd.o cms_cd.o cms_env.o cms_enc.o cms_ess.o \
	cms_pwri.o cms_kari.o

SRC_crypto_cms= $(LIBSRC_crypto_cms)

EXHEADER_crypto_cms=  cms.h
HEADER_crypto_cms=	cms_lcl.h $(EXHEADER_crypto_cms)

ALL_crypto_cms=    $(GENERAL_crypto_cms) $(SRC_crypto_cms) $(HEADER_crypto_cms)

top: top_crypto_cms
top_crypto_cms:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_cms) sub_all)

test: test_crypto_cms
test_crypto_cms:

all: all_crypto_cms
all_crypto_cms:	lib

lib: lib_crypto_cms
lib_crypto_cms:	$(LIBOBJ_crypto_cms)
	$(ARX) $(LIB_crypto_cms) $(LIBOBJ_crypto_cms)
	$(RANLIB) $(LIB_crypto_cms) || echo Never mind.
	@touch lib

files: files_crypto_cms
files_crypto_cms:
	$(PERL) $(TOP_crypto_cms)/util/files.pl TOP=$(TOP_crypto_cms) Makefile >> $(TOP_crypto_cms)/MINFO

links: links_crypto_cms
links_crypto_cms:
	@$(PERL) $(TOP_crypto_cms)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_cms)
	@$(PERL) $(TOP_crypto_cms)/util/mklink.pl ../../test $(TEST_crypto_cms)
	@$(PERL) $(TOP_crypto_cms)/util/mklink.pl ../../apps $(APPS_crypto_cms)

install: install_crypto_cms
install_crypto_cms:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_cms)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_cms
tags_crypto_cms:
	ctags $(SRC_crypto_cms)

tests: tests_crypto_cms
tests_crypto_cms:

lint: lint_crypto_cms
lint_crypto_cms:
	lint -DLINT $(INCLUDES_crypto_cms) $(SRC_crypto_cms)>fluff

dclean: dclean_crypto_cms
dclean_crypto_cms:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_cms
clean_crypto_cms:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_cms) $(CPPFLAGS) -c -o $@ $<
