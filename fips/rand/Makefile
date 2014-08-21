#
# OpenSSL/fips/rand/Makefile
#

DIR=	rand
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

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
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

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

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_drbg_ctr.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_ctr.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_ctr.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbg_ctr.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_drbg_ctr.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_drbg_ctr.o: ../../include/openssl/obj_mac.h
fips_drbg_ctr.o: ../../include/openssl/objects.h
fips_drbg_ctr.o: ../../include/openssl/opensslconf.h
fips_drbg_ctr.o: ../../include/openssl/opensslv.h
fips_drbg_ctr.o: ../../include/openssl/ossl_typ.h
fips_drbg_ctr.o: ../../include/openssl/safestack.h
fips_drbg_ctr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_drbg_ctr.o: fips_drbg_ctr.c fips_rand_lcl.h
fips_drbg_ec.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_ec.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_drbg_ec.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_drbg_ec.o: ../../include/openssl/ec.h ../../include/openssl/evp.h
fips_drbg_ec.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_drbg_ec.o: ../../include/openssl/hmac.h ../../include/openssl/obj_mac.h
fips_drbg_ec.o: ../../include/openssl/objects.h
fips_drbg_ec.o: ../../include/openssl/opensslconf.h
fips_drbg_ec.o: ../../include/openssl/opensslv.h
fips_drbg_ec.o: ../../include/openssl/ossl_typ.h
fips_drbg_ec.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_drbg_ec.o: ../../include/openssl/symhacks.h fips_drbg_ec.c fips_rand_lcl.h
fips_drbg_hash.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_hash.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_hash.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbg_hash.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_drbg_hash.o: ../../include/openssl/fips_rand.h
fips_drbg_hash.o: ../../include/openssl/hmac.h ../../include/openssl/obj_mac.h
fips_drbg_hash.o: ../../include/openssl/objects.h
fips_drbg_hash.o: ../../include/openssl/opensslconf.h
fips_drbg_hash.o: ../../include/openssl/opensslv.h
fips_drbg_hash.o: ../../include/openssl/ossl_typ.h
fips_drbg_hash.o: ../../include/openssl/safestack.h
fips_drbg_hash.o: ../../include/openssl/stack.h
fips_drbg_hash.o: ../../include/openssl/symhacks.h fips_drbg_hash.c
fips_drbg_hash.o: fips_rand_lcl.h
fips_drbg_hmac.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_hmac.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_hmac.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbg_hmac.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_drbg_hmac.o: ../../include/openssl/fips_rand.h
fips_drbg_hmac.o: ../../include/openssl/hmac.h ../../include/openssl/obj_mac.h
fips_drbg_hmac.o: ../../include/openssl/objects.h
fips_drbg_hmac.o: ../../include/openssl/opensslconf.h
fips_drbg_hmac.o: ../../include/openssl/opensslv.h
fips_drbg_hmac.o: ../../include/openssl/ossl_typ.h
fips_drbg_hmac.o: ../../include/openssl/safestack.h
fips_drbg_hmac.o: ../../include/openssl/stack.h
fips_drbg_hmac.o: ../../include/openssl/symhacks.h fips_drbg_hmac.c
fips_drbg_hmac.o: fips_rand_lcl.h
fips_drbg_lib.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_lib.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbg_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_drbg_lib.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_drbg_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_drbg_lib.o: ../../include/openssl/objects.h
fips_drbg_lib.o: ../../include/openssl/opensslconf.h
fips_drbg_lib.o: ../../include/openssl/opensslv.h
fips_drbg_lib.o: ../../include/openssl/ossl_typ.h
fips_drbg_lib.o: ../../include/openssl/safestack.h
fips_drbg_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_drbg_lib.o: fips_drbg_lib.c fips_rand_lcl.h
fips_drbg_rand.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_rand.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_rand.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbg_rand.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_drbg_rand.o: ../../include/openssl/fips_rand.h
fips_drbg_rand.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_drbg_rand.o: ../../include/openssl/obj_mac.h
fips_drbg_rand.o: ../../include/openssl/objects.h
fips_drbg_rand.o: ../../include/openssl/opensslconf.h
fips_drbg_rand.o: ../../include/openssl/opensslv.h
fips_drbg_rand.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_drbg_rand.o: ../../include/openssl/safestack.h
fips_drbg_rand.o: ../../include/openssl/stack.h
fips_drbg_rand.o: ../../include/openssl/symhacks.h fips_drbg_rand.c
fips_drbg_rand.o: fips_rand_lcl.h
fips_drbg_selftest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_selftest.o: ../../include/openssl/bio.h
fips_drbg_selftest.o: ../../include/openssl/crypto.h
fips_drbg_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbg_selftest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_drbg_selftest.o: ../../include/openssl/fips_rand.h
fips_drbg_selftest.o: ../../include/openssl/hmac.h
fips_drbg_selftest.o: ../../include/openssl/lhash.h
fips_drbg_selftest.o: ../../include/openssl/obj_mac.h
fips_drbg_selftest.o: ../../include/openssl/objects.h
fips_drbg_selftest.o: ../../include/openssl/opensslconf.h
fips_drbg_selftest.o: ../../include/openssl/opensslv.h
fips_drbg_selftest.o: ../../include/openssl/ossl_typ.h
fips_drbg_selftest.o: ../../include/openssl/safestack.h
fips_drbg_selftest.o: ../../include/openssl/stack.h
fips_drbg_selftest.o: ../../include/openssl/symhacks.h ../fips_locl.h
fips_drbg_selftest.o: fips_drbg_selftest.c fips_drbg_selftest.h fips_rand_lcl.h
fips_drbgvs.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbgvs.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_drbgvs.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
fips_drbgvs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_drbgvs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_drbgvs.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_drbgvs.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_drbgvs.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_drbgvs.o: ../../include/openssl/opensslconf.h
fips_drbgvs.o: ../../include/openssl/opensslv.h
fips_drbgvs.o: ../../include/openssl/ossl_typ.h
fips_drbgvs.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_drbgvs.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_drbgvs.c
fips_rand.o: ../../e_os.h ../../include/openssl/aes.h
fips_rand.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rand.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_rand.o: ../../include/openssl/ec.h ../../include/openssl/err.h
fips_rand.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_rand.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_rand.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_rand.o: ../../include/openssl/objects.h
fips_rand.o: ../../include/openssl/opensslconf.h
fips_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_rand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
fips_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rand.o: ../fips_locl.h fips_rand.c
fips_rand_lib.o: ../../e_os.h ../../include/openssl/aes.h
fips_rand_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rand_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_rand_lib.o: ../../include/openssl/ec.h ../../include/openssl/err.h
fips_rand_lib.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_rand_lib.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_rand_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_rand_lib.o: ../../include/openssl/objects.h
fips_rand_lib.o: ../../include/openssl/opensslconf.h
fips_rand_lib.o: ../../include/openssl/opensslv.h
fips_rand_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_rand_lib.o: ../../include/openssl/safestack.h
fips_rand_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rand_lib.o: fips_rand_lib.c
fips_rand_selftest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_rand_selftest.o: ../../include/openssl/bio.h
fips_rand_selftest.o: ../../include/openssl/crypto.h
fips_rand_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_rand_selftest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_rand_selftest.o: ../../include/openssl/fips.h
fips_rand_selftest.o: ../../include/openssl/fips_rand.h
fips_rand_selftest.o: ../../include/openssl/hmac.h
fips_rand_selftest.o: ../../include/openssl/lhash.h
fips_rand_selftest.o: ../../include/openssl/obj_mac.h
fips_rand_selftest.o: ../../include/openssl/objects.h
fips_rand_selftest.o: ../../include/openssl/opensslconf.h
fips_rand_selftest.o: ../../include/openssl/opensslv.h
fips_rand_selftest.o: ../../include/openssl/ossl_typ.h
fips_rand_selftest.o: ../../include/openssl/rand.h
fips_rand_selftest.o: ../../include/openssl/safestack.h
fips_rand_selftest.o: ../../include/openssl/stack.h
fips_rand_selftest.o: ../../include/openssl/symhacks.h ../fips_locl.h
fips_rand_selftest.o: fips_rand_selftest.c
fips_randtest.o: ../../e_os.h ../../include/openssl/aes.h
fips_randtest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_randtest.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_randtest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_randtest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_randtest.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_randtest.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_randtest.o: ../../include/openssl/obj_mac.h
fips_randtest.o: ../../include/openssl/objects.h
fips_randtest.o: ../../include/openssl/opensslconf.h
fips_randtest.o: ../../include/openssl/opensslv.h
fips_randtest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_randtest.o: ../../include/openssl/safestack.h
fips_randtest.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_randtest.o: ../fips_utl.h fips_randtest.c
fips_rngvs.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_rngvs.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_rngvs.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
fips_rngvs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_rngvs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_rngvs.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_rngvs.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_rngvs.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_rngvs.o: ../../include/openssl/opensslconf.h
fips_rngvs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_rngvs.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
fips_rngvs.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rngvs.o: ../fips_utl.h fips_rngvs.c
