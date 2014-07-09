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

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

Q=../testvectors/cmac/req
A=../testvectors/cmac/rsp

fips_test:
	-rm -rf $(A)
	mkdir $(A)
	if [ -f $(Q)/CMACGenAES256.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_cmactest -g < $(Q)/CMACGenAES256.req > $(A)/CMACGenAES256.rsp; fi
	if [ -f $(Q)/CMACVerAES256.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_cmactest -v < $(Q)/CMACVerAES256.req > $(A)/CMACVerAES256.rsp; fi

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
