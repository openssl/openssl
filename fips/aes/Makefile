#
# OpenSSL/fips/aes/Makefile
#

DIR=	aes
INCLUDES=

ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=fips_aesavs.c fips_gcmtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_aes_selftest.c
LIBOBJ=fips_aes_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_aes
top_fips_aes:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_aes
all_fips_aes:	lib

lib: lib_fips_aes
lib_fips_aes:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_aes
files_fips_aes:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_aes
links_fips_aes:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_aes
install_fips_aes:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_aes
tags_fips_aes:
	ctags $(SRC)

tests: tests_fips_aes
tests_fips_aes:

fips_test: fips_test_fips_aes
fips_test_fips_aes:
	-find ../testvectors/aes/req -name '*.req' > testlist
	-rm -rf ../testvectors/aes/rsp
	mkdir ../testvectors/aes/rsp
	if [ -s testlist ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_aesavs -d testlist; fi

lint: lint_fips_aes
lint_fips_aes:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_aes
dclean_fips_aes:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_aes
clean_fips_aes:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff testlist
