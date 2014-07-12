#
# OpenSSL/fips/ecdh/Makefile
#

DIR=	ecdh
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_ecdhvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_ecdh_selftest.c
LIBOBJ= fips_ecdh_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_ecdh
top_fips_ecdh:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_ecdh
all_fips_ecdh:	lib

lib: lib_fips_ecdh
lib_fips_ecdh:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_ecdh
files_fips_ecdh:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_ecdh
links_fips_ecdh:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_ecdh
install_fips_ecdh:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_ecdh
tags_fips_ecdh:
	ctags $(SRC)

tests: tests_fips_ecdh
tests_fips_ecdh:

fips_test: fips_test_fips_ecdh
fips_test_fips_ecdh:

lint: lint_fips_ecdh
lint_fips_ecdh:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_ecdh
dclean_fips_ecdh:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_ecdh
clean_fips_ecdh:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
