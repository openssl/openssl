#
# OpenSSL/fips/rand/Makefile
#

DIR_fips_rand=	rand
INCLUDES_fips_rand=

CFLAGS_fips_rand= $(INCLUDES_fips_rand) $(CFLAG)

GENERAL_fips_rand=Makefile
TEST_fips_rand= fips_randtest.c fips_rngvs.c fips_drbgvs.c
APPS_fips_rand=

LIB_fips_rand=$(TOP_fips_rand)/libcrypto.a
LIBSRC_fips_rand=	fips_rand.c fips_rand_selftest.c fips_drbg_lib.c \
	fips_drbg_hash.c fips_drbg_hmac.c fips_drbg_ctr.c fips_drbg_ec.c \
	fips_drbg_selftest.c fips_drbg_rand.c fips_rand_lib.c
LIBOBJ_fips_rand=	fips_rand.o fips_rand_selftest.o fips_drbg_lib.o \
	fips_drbg_hash.o fips_drbg_hmac.o fips_drbg_ctr.o fips_drbg_ec.o \
	fips_drbg_selftest.o fips_drbg_rand.o fips_rand_lib.o

SRC_fips_rand= $(LIBSRC_fips_rand)

EXHEADER_fips_rand= fips_rand.h
HEADER_fips_rand=	$(EXHEADER_fips_rand) fips_rand_lcl.h fips_drbg_selftest.h

ALL_fips_rand=    $(GENERAL_fips_rand) $(SRC_fips_rand) $(HEADER_fips_rand)

top: top_fips_rand
top_fips_rand:
	(cd $(TOP_fips_rand); $(MAKE) DIRS=fips SDIRS=$(DIR_fips_rand) sub_all)

all: all_fips_rand
all_fips_rand:	lib

lib:	$(LIBOBJ_fips_rand)
	@echo $(LIBOBJ_fips_rand) > lib

files: files_fips_rand
files_fips_rand:
	$(PERL) $(TOP_fips_rand)/util/files.pl TOP=$(TOP_fips_rand) Makefile >> $(TOP_fips_rand)/MINFO

links: links_fips_rand
links_fips_rand:
	@$(PERL) $(TOP_fips_rand)/util/mklink.pl $(TOP_fips_rand)/include/openssl $(EXHEADER_fips_rand)
	@$(PERL) $(TOP_fips_rand)/util/mklink.pl $(TOP_fips_rand)/test $(TEST_fips_rand)
	@$(PERL) $(TOP_fips_rand)/util/mklink.pl $(TOP_fips_rand)/apps $(APPS_fips_rand)

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
	if [ -f $(Q_fips_rand)/ANSI931_AES128MCT.req ]; then $(TOP_fips_rand)/util/shlib_wrap.sh $(TOP_fips_rand)/test/fips_rngvs mct < $(Q_fips_rand)/ANSI931_AES128MCT.req > $(A_fips_rand)/ANSI931_AES128MCT.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES192MCT.req ]; then $(TOP_fips_rand)/util/shlib_wrap.sh $(TOP_fips_rand)/test/fips_rngvs mct < $(Q_fips_rand)/ANSI931_AES192MCT.req > $(A_fips_rand)/ANSI931_AES192MCT.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES256MCT.req ]; then $(TOP_fips_rand)/util/shlib_wrap.sh $(TOP_fips_rand)/test/fips_rngvs mct < $(Q_fips_rand)/ANSI931_AES256MCT.req > $(A_fips_rand)/ANSI931_AES256MCT.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES128VST.req ]; then $(TOP_fips_rand)/util/shlib_wrap.sh $(TOP_fips_rand)/test/fips_rngvs vst < $(Q_fips_rand)/ANSI931_AES128VST.req > $(A_fips_rand)/ANSI931_AES128VST.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES192VST.req ]; then $(TOP_fips_rand)/util/shlib_wrap.sh $(TOP_fips_rand)/test/fips_rngvs vst < $(Q_fips_rand)/ANSI931_AES192VST.req > $(A_fips_rand)/ANSI931_AES192VST.rsp; fi
	if [ -f $(Q_fips_rand)/ANSI931_AES256VST.req ]; then $(TOP_fips_rand)/util/shlib_wrap.sh $(TOP_fips_rand)/test/fips_rngvs vst < $(Q_fips_rand)/ANSI931_AES256VST.req > $(A_fips_rand)/ANSI931_AES256VST.rsp; fi

lint: lint_fips_rand
lint_fips_rand:
	lint -DLINT $(INCLUDES_fips_rand) $(SRC_fips_rand)>fluff

dclean: dclean_fips_rand
dclean_fips_rand:

clean: clean_fips_rand
clean_fips_rand:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_rand) $(CPPFLAGS) -c -o $@ $<
