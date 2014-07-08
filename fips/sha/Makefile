#
# OpenSSL/fips/sha/Makefile
#

DIR=	sha
INCLUDES=

ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_shatest.c
APPS=
EXE= fips_standalone_sha1$(EXE_EXT)

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_sha1_selftest.c
LIBOBJ=fips_sha1_selftest.o

SRC= $(LIBSRC)
PROGS= fips_standalone_sha1.c

EXHEADER=
HEADER=	

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips SDIRS=$(DIR) sub_all)

all:	../fips_standalone_sha1$(EXE_EXT) lib

lib:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

../fips_standalone_sha1$(EXE_EXT): fips_standalone_sha1.o
	if [ -z "$(HOSTCC)" ] ; then \
	FIPS_SHA_ASM=""; for i in $(SHA1_ASM_OBJ) sha1dgst.o ; do FIPS_SHA_ASM="$$FIPS_SHA_ASM ../../crypto/sha/$$i" ; done; \
	$(CC) -o $@ $(CFLAGS) fips_standalone_sha1.o $$FIPS_SHA_ASM ; \
	else \
		$(HOSTCC) $(HOSTCFLAGS) -o $ $@ -I../../include -I../../crypto fips_standalone_sha1.c ../../crypto/sha/sha1dgst.c ; \
	fi

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

Q=../testvectors/sha/req
A=../testvectors/sha/rsp

VECTORS = SHA1LongMsg \
	SHA1Monte \
	SHA1ShortMsg \
	SHA224LongMsg \
	SHA224Monte \
	SHA224ShortMsg \
	SHA256LongMsg \
	SHA256Monte \
	SHA256ShortMsg \
	SHA384LongMsg \
	SHA384Monte \
	SHA384ShortMsg \
	SHA512LongMsg \
	SHA512Monte \
	SHA512ShortMsg

fips_test:
	-rm -rf $(A)
	mkdir $(A)
	for file in $(VECTORS); do \
	    if [ -f $(Q)/$$file.req ]; then \
		$(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_shatest $(Q)/$$file.req $(A)/$$file.rsp; \
	    fi; \
	done

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_sha1_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_sha1_selftest.o: ../../include/openssl/crypto.h
fips_sha1_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_sha1_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_sha1_selftest.o: ../../include/openssl/lhash.h
fips_sha1_selftest.o: ../../include/openssl/obj_mac.h
fips_sha1_selftest.o: ../../include/openssl/objects.h
fips_sha1_selftest.o: ../../include/openssl/opensslconf.h
fips_sha1_selftest.o: ../../include/openssl/opensslv.h
fips_sha1_selftest.o: ../../include/openssl/ossl_typ.h
fips_sha1_selftest.o: ../../include/openssl/safestack.h
fips_sha1_selftest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_sha1_selftest.o: ../../include/openssl/symhacks.h fips_sha1_selftest.c
fips_shatest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_shatest.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
fips_shatest.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_shatest.o: ../../include/openssl/ec.h ../../include/openssl/err.h
fips_shatest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_shatest.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_shatest.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_shatest.o: ../../include/openssl/objects.h
fips_shatest.o: ../../include/openssl/opensslconf.h
fips_shatest.o: ../../include/openssl/opensslv.h
fips_shatest.o: ../../include/openssl/ossl_typ.h
fips_shatest.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_shatest.o: ../../include/openssl/symhacks.h ../fips_utl.h fips_shatest.c
fips_standalone_sha1.o: ../../include/openssl/asn1.h
fips_standalone_sha1.o: ../../include/openssl/bio.h
fips_standalone_sha1.o: ../../include/openssl/crypto.h
fips_standalone_sha1.o: ../../include/openssl/e_os2.h
fips_standalone_sha1.o: ../../include/openssl/evp.h
fips_standalone_sha1.o: ../../include/openssl/fips.h
fips_standalone_sha1.o: ../../include/openssl/hmac.h
fips_standalone_sha1.o: ../../include/openssl/obj_mac.h
fips_standalone_sha1.o: ../../include/openssl/objects.h
fips_standalone_sha1.o: ../../include/openssl/opensslconf.h
fips_standalone_sha1.o: ../../include/openssl/opensslv.h
fips_standalone_sha1.o: ../../include/openssl/ossl_typ.h
fips_standalone_sha1.o: ../../include/openssl/safestack.h
fips_standalone_sha1.o: ../../include/openssl/sha.h
fips_standalone_sha1.o: ../../include/openssl/stack.h
fips_standalone_sha1.o: ../../include/openssl/symhacks.h fips_standalone_sha1.c
