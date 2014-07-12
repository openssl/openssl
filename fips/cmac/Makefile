#
# OpenSSL/fips/cmac/Makefile
#

DIR=	cmac
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=fips_cmactest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_cmac_selftest.c
LIBOBJ= fips_cmac_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_cmac
top_fips_cmac:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_cmac
all_fips_cmac:	lib

lib: lib_fips_cmac
lib_fips_cmac:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_cmac
files_fips_cmac:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_cmac
links_fips_cmac:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_cmac
install_fips_cmac:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_cmac
tags_fips_cmac:
	ctags $(SRC)

tests: tests_fips_cmac
tests_fips_cmac:

Q=../testvectors/cmac/req
A=../testvectors/cmac/rsp

fips_test: fips_test_fips_cmac
fips_test_fips_cmac:
	-rm -rf $(A)
	mkdir $(A)
	if [ -f $(Q)/CMACGenAES256.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_cmactest -g < $(Q)/CMACGenAES256.req > $(A)/CMACGenAES256.rsp; fi
	if [ -f $(Q)/CMACVerAES256.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_cmactest -v < $(Q)/CMACVerAES256.req > $(A)/CMACVerAES256.rsp; fi

lint: lint_fips_cmac
lint_fips_cmac:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_cmac
dclean_fips_cmac:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_cmac
clean_fips_cmac:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
