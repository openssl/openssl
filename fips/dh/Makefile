#
# OpenSSL/fips/dh/Makefile
#

DIR=	dh
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_dhvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_dh_lib.c
LIBOBJ= fips_dh_lib.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_dh
top_fips_dh:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_dh
all_fips_dh:	lib

lib: lib_fips_dh
lib_fips_dh:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_dh
files_fips_dh:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_dh
links_fips_dh:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_dh
install_fips_dh:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_dh
tags_fips_dh:
	ctags $(SRC)

tests: tests_fips_dh
tests_fips_dh:

fips_test: fips_test_fips_dh
fips_test_fips_dh:

lint: lint_fips_dh
lint_fips_dh:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_dh
dclean_fips_dh:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_dh
clean_fips_dh:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

