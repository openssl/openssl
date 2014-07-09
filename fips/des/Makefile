#
# OpenSSL/fips/des/Makefile
#

DIR=	des
INCLUDES=

ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_desmovs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_des_selftest.c
LIBOBJ=fips_des_selftest.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=

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
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags:
	ctags $(SRC)

tests:

fips_test:
	-find ../testvectors/tdes/req -name '*.req' > testlist
	-rm -rf ../testvectors/tdes/rsp
	mkdir ../testvectors/tdes/rsp
	if [ -s testlist ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_desmovs -d testlist; fi

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff testlist
