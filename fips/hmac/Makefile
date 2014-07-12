#
# OpenSSL/fips/hmac/Makefile
#

DIR=	hmac
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=fips_hmactest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_hmac_selftest.c
LIBOBJ= fips_hmac_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_hmac
top_fips_hmac:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_hmac
all_fips_hmac:	lib

lib: lib_fips_hmac
lib_fips_hmac:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_hmac
files_fips_hmac:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_hmac
links_fips_hmac:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_hmac
install_fips_hmac:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_hmac
tags_fips_hmac:
	ctags $(SRC)

tests: tests_fips_hmac
tests_fips_hmac:

Q=../testvectors/hmac/req
A=../testvectors/hmac/rsp

fips_test: fips_test_fips_hmac
fips_test_fips_hmac:
	-rm -rf $(A)
	mkdir $(A)
	if [ -f $(Q)/HMAC.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_hmactest < $(Q)/HMAC.req > $(A)/HMAC.rsp; fi

lint: lint_fips_hmac
lint_fips_hmac:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_hmac
dclean_fips_hmac:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_hmac
clean_fips_hmac:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
