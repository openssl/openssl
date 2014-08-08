#
# OpenSSL/fips/rand/Makefile
#

INCLUDES_fips_rand=

CFLAGS_fips_rand= $(INCLUDES_fips_rand) $(CFLAG)

GENERAL_fips_rand=fips/rand/Makefile
TEST_fips_rand= fips/rand/fips_randtest.c fips/rand/fips_rngvs.c fips/rand/fips_drbgvs.c
APPS_fips_rand=

LIB_fips_rand=libcrypto.a
LIBSRC_fips_rand=	fips/rand/fips_rand.c fips/rand/fips_rand_selftest.c fips/rand/fips_drbg_lib.c \
	fips/rand/fips_drbg_hash.c fips/rand/fips_drbg_hmac.c fips/rand/fips_drbg_ctr.c fips/rand/fips_drbg_ec.c \
	fips/rand/fips_drbg_selftest.c fips/rand/fips_drbg_rand.c fips/rand/fips_rand_lib.c
LIBOBJ_fips_rand=	fips/rand/fips_rand.o fips/rand/fips_rand_selftest.o fips/rand/fips_drbg_lib.o \
	fips/rand/fips_drbg_hash.o fips/rand/fips_drbg_hmac.o fips/rand/fips_drbg_ctr.o fips/rand/fips_drbg_ec.o \
	fips/rand/fips_drbg_selftest.o fips/rand/fips_drbg_rand.o fips/rand/fips_rand_lib.o

SRC_fips_rand= $(LIBSRC_fips_rand)

EXHEADER_fips_rand= fips/rand/fips_rand.h
HEADER_fips_rand=	$(EXHEADER_fips_rand) fips/rand/fips_rand_lcl.h fips/rand/fips_drbg_selftest.h

ALL_fips_rand=    $(GENERAL_fips_rand) $(SRC_fips_rand) $(HEADER_fips_rand)


all: all_fips_rand
all_fips_rand:	fips/rand/lib

fips/rand/lib:	$(LIBOBJ_fips_rand)
	@echo $(LIBOBJ_fips_rand) > fips/rand/lib

files: files_fips_rand
files_fips_rand:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_rand
links_fips_rand:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_rand)
	@$(PERL) util/mklink.pl test $(TEST_fips_rand)
	@$(PERL) util/mklink.pl apps $(APPS_fips_rand)

install: install_fips_rand
install_fips_rand:
	@headerlist="$(EXHEADER_fips_rand)"; for i in $$headerlist; \
	do \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_rand
tags_fips_rand:
	ctags $(SRC_fips_rand)

tests: tests_fips_rand
tests_fips_rand:

Q_fips_rand=../testvectors/rng/req
A_fips_rand=../testvectors/rng/rsp

fips_test: fips_test_fips_rand
fips_test_fips_rand:
	-rm -rf $(A_fips_rand)
	mkdir $(A_fips_rand)
	if [ -f $(Q_fips_rand)/ANSI931_AES128MCT.req ]; then util/shlib_wrap.sh test/fips_rngvs mct < $(Q_fips_rand)/ANSI931_AES128MCT.req > $(A_fips_rand)/ANSI931_AES128MCT.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES192MCT.req ]; then util/shlib_wrap.sh test/fips_rngvs mct < $(Q_fips_rand)/ANSI931_AES192MCT.req > $(A_fips_rand)/ANSI931_AES192MCT.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES256MCT.req ]; then util/shlib_wrap.sh test/fips_rngvs mct < $(Q_fips_rand)/ANSI931_AES256MCT.req > $(A_fips_rand)/ANSI931_AES256MCT.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES128VST.req ]; then util/shlib_wrap.sh test/fips_rngvs vst < $(Q_fips_rand)/ANSI931_AES128VST.req > $(A_fips_rand)/ANSI931_AES128VST.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES192VST.req ]; then util/shlib_wrap.sh test/fips_rngvs vst < $(Q_fips_rand)/ANSI931_AES192VST.req > $(A_fips_rand)/ANSI931_AES192VST.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES256VST.req ]; then util/shlib_wrap.sh test/fips_rngvs vst < $(Q_fips_rand)/ANSI931_AES256VST.req > $(A_fips_rand)/ANSI931_AES256VST.rsp; fi

lint: lint_fips_rand
lint_fips_rand:
	lint -DLINT $(INCLUDES_fips_rand) $(SRC_fips_rand)>fips/rand/fluff

dclean: dclean_fips_rand
dclean_fips_rand:

clean: clean_fips_rand
clean_fips_rand:
	rm -f fips/rand/*.o fips/rand/*.d fips/rand/*.obj fips/rand/lib fips/rand/tags fips/rand/core fips/rand/.pure fips/rand/.nfs* fips/rand/*.old fips/rand/*.bak fips/rand/fluff

