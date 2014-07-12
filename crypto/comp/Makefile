#
# OpenSSL/crypto/comp/Makefile
#

DIR=	comp
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= comp_lib.c comp_err.c \
	c_rle.c c_zlib.c

LIBOBJ=	comp_lib.o comp_err.o \
	c_rle.o c_zlib.o

SRC= $(LIBSRC)

EXHEADER= comp.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_crypto_comp
top_crypto_comp:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all: all_crypto_comp
all_crypto_comp:	lib

lib: lib_crypto_comp
lib_crypto_comp:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files: files_crypto_comp
files_crypto_comp:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_crypto_comp
links_crypto_comp:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: install_crypto_comp
install_crypto_comp:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_comp
tags_crypto_comp:
	ctags $(SRC)

tests: tests_crypto_comp
tests_crypto_comp:

lint: lint_crypto_comp
lint_crypto_comp:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_crypto_comp
dclean_crypto_comp:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_comp
clean_crypto_comp:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

