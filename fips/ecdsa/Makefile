#
# OpenSSL/fips/ecdsa/Makefile
#

DIR=	ecdsa
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_ecdsavs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_ecdsa_lib.c fips_ecdsa_sign.c fips_ecdsa_selftest.c
LIBOBJ= fips_ecdsa_lib.o fips_ecdsa_sign.o fips_ecdsa_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_ecdsa
top_fips_ecdsa:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_ecdsa
all_fips_ecdsa:	lib

lib: lib_fips_ecdsa
lib_fips_ecdsa:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_ecdsa
files_fips_ecdsa:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_ecdsa
links_fips_ecdsa:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_ecdsa
install_fips_ecdsa:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_ecdsa
tags_fips_ecdsa:
	ctags $(SRC)

tests: tests_fips_ecdsa
tests_fips_ecdsa:

fips_test: fips_test_fips_ecdsa
fips_test_fips_ecdsa:

lint: lint_fips_ecdsa
lint_fips_ecdsa:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_ecdsa
dclean_fips_ecdsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_ecdsa
clean_fips_ecdsa:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
