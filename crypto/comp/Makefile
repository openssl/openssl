#
# OpenSSL/crypto/comp/Makefile
#

INCLUDES_crypto_comp= -I.. -I$(TOP_crypto_comp) -I../../include

CFLAGS_crypto_comp= $(INCLUDES_crypto_comp) $(CFLAG)

GENERAL_crypto_comp=Makefile
TEST_crypto_comp=
APPS_crypto_comp=

LIB_crypto_comp=$(TOP_crypto_comp)/libcrypto.a
LIBSRC_crypto_comp= comp_lib.c comp_err.c \
	c_rle.c c_zlib.c

LIBOBJ_crypto_comp=	comp_lib.o comp_err.o \
	c_rle.o c_zlib.o

SRC_crypto_comp= $(LIBSRC_crypto_comp)

EXHEADER_crypto_comp= comp.h
HEADER_crypto_comp=	$(EXHEADER_crypto_comp)

ALL_crypto_comp=    $(GENERAL_crypto_comp) $(SRC_crypto_comp) $(HEADER_crypto_comp)


all: all_crypto_comp
all_crypto_comp:	lib

lib:	$(LIBOBJ_crypto_comp)
	$(ARX) $(LIB_crypto_comp) $(LIBOBJ_crypto_comp)
	$(RANLIB) $(LIB_crypto_comp) || echo Never mind.
	@touch lib

files: files_crypto_comp
files_crypto_comp:
	$(PERL) $(TOP_crypto_comp)/util/files.pl TOP=$(TOP_crypto_comp) Makefile >> $(TOP_crypto_comp)/MINFO

links: links_crypto_comp
links_crypto_comp:
	@$(PERL) $(TOP_crypto_comp)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_comp)
	@$(PERL) $(TOP_crypto_comp)/util/mklink.pl ../../test $(TEST_crypto_comp)
	@$(PERL) $(TOP_crypto_comp)/util/mklink.pl ../../apps $(APPS_crypto_comp)

install: install_crypto_comp
install_crypto_comp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_comp)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_comp
tags_crypto_comp:
	ctags $(SRC_crypto_comp)

tests: tests_crypto_comp
tests_crypto_comp:

lint: lint_crypto_comp
lint_crypto_comp:
	lint -DLINT $(INCLUDES_crypto_comp) $(SRC_crypto_comp)>fluff

dclean: dclean_crypto_comp
dclean_crypto_comp:

clean: clean_crypto_comp
clean_crypto_comp:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_comp) $(CPPFLAGS) -c -o $@ $<
