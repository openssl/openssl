#
# OpenSSL/fips/rand/Makefile
#

DIR=	rand
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_randtest.c fips_rngvs.c fips_drbgvs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	fips_rand.c fips_rand_selftest.c fips_drbg_lib.c \
	fips_drbg_hash.c fips_drbg_hmac.c fips_drbg_ctr.c fips_drbg_ec.c \
	fips_drbg_selftest.c fips_drbg_rand.c fips_rand_lib.c
LIBOBJ=	fips_rand.o fips_rand_selftest.o fips_drbg_lib.o \
	fips_drbg_hash.o fips_drbg_hmac.o fips_drbg_ctr.o fips_drbg_ec.o \
	fips_drbg_selftest.o fips_drbg_rand.o fips_rand_lib.o

SRC= $(LIBSRC)

EXHEADER= fips_rand.h
HEADER=	$(EXHEADER) fips_rand_lcl.h fips_drbg_selftest.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips SDIRS=$(DIR) sub_all)

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

Q=../testvectors/rng/req
A=../testvectors/rng/rsp

fips_test:
	-rm -rf $(A)
	mkdir $(A)
	if [ -f $(Q)/ANSI931_AES128MCT.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rngvs mct < $(Q)/ANSI931_AES128MCT.req > $(A)/ANSI931_AES128MCT.rsp; fi
	if [ -f $(Q)/ANSI931_AES192MCT.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rngvs mct < $(Q)/ANSI931_AES192MCT.req > $(A)/ANSI931_AES192MCT.rsp; fi
	if [ -f $(Q)/ANSI931_AES256MCT.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rngvs mct < $(Q)/ANSI931_AES256MCT.req > $(A)/ANSI931_AES256MCT.rsp; fi
	if [ -f $(Q)/ANSI931_AES128VST.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rngvs vst < $(Q)/ANSI931_AES128VST.req > $(A)/ANSI931_AES128VST.rsp; fi
	if [ -f $(Q)/ANSI931_AES192VST.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rngvs vst < $(Q)/ANSI931_AES192VST.req > $(A)/ANSI931_AES192VST.rsp; fi
	if [ -f $(Q)/ANSI931_AES256VST.req ]; then $(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_rngvs vst < $(Q)/ANSI931_AES256VST.req > $(A)/ANSI931_AES256VST.rsp; fi

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

