#
# OpenSSL/ocsp/Makefile
#

DIR_crypto_ocsp=	ocsp
INCLUDES_crypto_ocsp= -I.. -I$(TOP_crypto_ocsp) -I../../include

CFLAGS_crypto_ocsp= $(INCLUDES_crypto_ocsp) $(CFLAG)

GENERAL_crypto_ocsp=Makefile README
TEST_crypto_ocsp=
APPS_crypto_ocsp=

LIB_crypto_ocsp=$(TOP_crypto_ocsp)/libcrypto.a
LIBSRC_crypto_ocsp= ocsp_asn.c ocsp_ext.c ocsp_ht.c ocsp_lib.c ocsp_cl.c \
	ocsp_srv.c ocsp_prn.c ocsp_vfy.c ocsp_err.c

LIBOBJ_crypto_ocsp= ocsp_asn.o ocsp_ext.o ocsp_ht.o ocsp_lib.o ocsp_cl.o \
	ocsp_srv.o ocsp_prn.o ocsp_vfy.o ocsp_err.o

SRC_crypto_ocsp= $(LIBSRC_crypto_ocsp)

EXHEADER_crypto_ocsp= ocsp.h
HEADER_crypto_ocsp=	$(EXHEADER_crypto_ocsp)

ALL_crypto_ocsp=    $(GENERAL_crypto_ocsp) $(SRC_crypto_ocsp) $(HEADER_crypto_ocsp)

top: top_crypto_ocsp
top_crypto_ocsp:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_ocsp) sub_all)

all: all_crypto_ocsp
all_crypto_ocsp:	lib

lib:	$(LIBOBJ_crypto_ocsp)
	$(ARX) $(LIB_crypto_ocsp) $(LIBOBJ_crypto_ocsp)
	$(RANLIB) $(LIB_crypto_ocsp) || echo Never mind.
	@touch lib

files: files_crypto_ocsp
files_crypto_ocsp:
	$(PERL) $(TOP_crypto_ocsp)/util/files.pl TOP=$(TOP_crypto_ocsp) Makefile >> $(TOP_crypto_ocsp)/MINFO

links: links_crypto_ocsp
links_crypto_ocsp:
	@$(PERL) $(TOP_crypto_ocsp)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ocsp)
	@$(PERL) $(TOP_crypto_ocsp)/util/mklink.pl ../../test $(TEST_crypto_ocsp)
	@$(PERL) $(TOP_crypto_ocsp)/util/mklink.pl ../../apps $(APPS_crypto_ocsp)

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
	lint -DLINT $(INCLUDES_crypto_ocsp) $(SRC_crypto_ocsp)>fluff

dclean: dclean_crypto_ocsp
dclean_crypto_ocsp:

clean: clean_crypto_ocsp
clean_crypto_ocsp:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_ocsp) $(CPPFLAGS) -c -o $@ $<
