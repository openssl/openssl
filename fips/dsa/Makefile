#
# OpenSSL/fips/dsa/Makefile
#

DIR=	dsa
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=fips_dsatest.c fips_dssvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_dsa_selftest.c \
	fips_dsa_lib.c fips_dsa_sign.c
LIBOBJ= fips_dsa_selftest.o \
	fips_dsa_lib.o fips_dsa_sign.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_dsa
top_fips_dsa:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_dsa
all_fips_dsa:	lib

lib: lib_fips_dsa
lib_fips_dsa:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_dsa
files_fips_dsa:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_dsa
links_fips_dsa:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_dsa
install_fips_dsa:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_dsa
tags_fips_dsa:
	ctags $(SRC)

tests: tests_fips_dsa
tests_fips_dsa:

Q=../testvectors/dsa/req
A=../testvectors/dsa/rsp

fips_test: fips_test_fips_dsa
fips_test_fips_dsa:
	-rm -rf $A
	mkdir $A
	if [ -f $(Q)/PQGGen.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs pqg < $(Q)/PQGGen.req > $(A)/PQGGen.rsp; fi
	if [ -f $(Q)/KeyPair.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs keypair < $(Q)/KeyPair.req > $(A)/KeyPair.rsp; fi
	if [ -f $(Q)/SigGen.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs siggen < $(Q)/SigGen.req > $(A)/SigGen.rsp; fi
	if [ -f $(Q)/SigVer.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_dssvs sigver < $Q/SigVer.req > $A/SigVer.rsp; fi

lint: lint_fips_dsa
lint_fips_dsa:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_dsa
dclean_fips_dsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_dsa
clean_fips_dsa:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
