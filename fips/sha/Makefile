#
# SSLeay/fips/sha1/Makefile
#

DIR=	sha
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
EXE_EXT=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_sha1test.c
TESTDATA= sha1vectors.txt sha1hashes.txt
APPS=
EXE= fips_standalone_sha1$(EXE_EXT)

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_sha1dgst.c fips_sha1_selftest.c asm/fips-sx86-elf.s \
	fips_sha256.c fips_sha512.c
LIBOBJ=fips_sha1dgst.o fips_sha1_selftest.o $(FIPS_SHA1_ASM_OBJ) \
	fips_sha256.o fips_sha512.o

SRC= $(LIBSRC) fips_standalone_sha1.c

EXHEADER=fips_sha.h
HEADER=	$(EXHEADER) fips_sha_locl.h fips_md32_common.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips SDIRS=$(DIR) sub_all)

all:	fips_standalone_sha1$(EXE_EXT) lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@sleep 2; touch lib

fips_standalone_sha1$(EXE_EXT): fips_standalone_sha1.o fips_sha1dgst.o $(FIPS_SHA1_ASM_OBJ)
	$(CC) -o fips_standalone_sha1$(EXE_EXT) $(CFLAGS) \
		fips_standalone_sha1.o fips_sha1dgst.o $(FIPS_SHA1_ASM_OBJ)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	cp $(TESTDATA) $(TOP)/test
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

top_fips_sha1test:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) TARGET=fips_sha1test sub_target)

fips_sha1test: fips_sha1test.o $(TOP)/libcrypto.a
	$(CC) $(CFLAGS) -o fips_sha1test fips_sha1test.o $(PEX_LIBS) $(TOP)/libcrypto.a $(EX_LIBS)
	TOP=$(TOP) $(TOP)/fips/openssl_fips_fingerprint $(TOP)/libcrypto.a fips_sha1test

fips_test: top_fips_sha1test
	-rm -rf ../testvectors/sha1/rsp
	mkdir ../testvectors/sha1/rsp
	./fips_sha1test ../testvectors/sha1/req/sha.req  > ../testvectors/sha1/rsp/sha.rsp

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(SRC) $(TEST)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_sha1_selftest.o: ../../include/openssl/bio.h
fips_sha1_selftest.o: ../../include/openssl/crypto.h
fips_sha1_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_sha1_selftest.o: ../../include/openssl/fips.h
fips_sha1_selftest.o: ../../include/openssl/fips_sha.h
fips_sha1_selftest.o: ../../include/openssl/lhash.h
fips_sha1_selftest.o: ../../include/openssl/opensslconf.h
fips_sha1_selftest.o: ../../include/openssl/opensslv.h
fips_sha1_selftest.o: ../../include/openssl/safestack.h
fips_sha1_selftest.o: ../../include/openssl/stack.h
fips_sha1_selftest.o: ../../include/openssl/symhacks.h fips_sha1_selftest.c
fips_sha1dgst.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_sha1dgst.o: ../../include/openssl/opensslconf.h
fips_sha1dgst.o: ../../include/openssl/opensslv.h
fips_sha1dgst.o: ../../include/openssl/safestack.h
fips_sha1dgst.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_sha1dgst.o: fips_sha1dgst.c
fips_sha1test.o: ../../e_os.h ../../include/openssl/bio.h
fips_sha1test.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_sha1test.o: ../../include/openssl/err.h ../../include/openssl/fips.h
fips_sha1test.o: ../../include/openssl/fips_sha.h ../../include/openssl/lhash.h
fips_sha1test.o: ../../include/openssl/opensslconf.h
fips_sha1test.o: ../../include/openssl/opensslv.h
fips_sha1test.o: ../../include/openssl/safestack.h
fips_sha1test.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_sha1test.o: fips_sha1test.c
fips_sha256.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_sha256.o: ../../include/openssl/fips.h ../../include/openssl/fips_sha.h
fips_sha256.o: ../../include/openssl/opensslconf.h
fips_sha256.o: ../../include/openssl/opensslv.h
fips_sha256.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_sha256.o: ../../include/openssl/symhacks.h fips_md32_common.h
fips_sha256.o: fips_sha256.c
fips_sha512.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_sha512.o: ../../include/openssl/fips.h ../../include/openssl/fips_sha.h
fips_sha512.o: ../../include/openssl/opensslconf.h
fips_sha512.o: ../../include/openssl/opensslv.h
fips_sha512.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_sha512.o: ../../include/openssl/symhacks.h fips_sha512.c
fips_standalone_sha1.o: ../../include/openssl/aes.h
fips_standalone_sha1.o: ../../include/openssl/asn1.h
fips_standalone_sha1.o: ../../include/openssl/bio.h
fips_standalone_sha1.o: ../../include/openssl/blowfish.h
fips_standalone_sha1.o: ../../include/openssl/bn.h ../../include/openssl/cast.h
fips_standalone_sha1.o: ../../include/openssl/crypto.h
fips_standalone_sha1.o: ../../include/openssl/des.h
fips_standalone_sha1.o: ../../include/openssl/des_old.h
fips_standalone_sha1.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
fips_standalone_sha1.o: ../../include/openssl/e_os2.h
fips_standalone_sha1.o: ../../include/openssl/evp.h
fips_standalone_sha1.o: ../../include/openssl/fips_sha.h
fips_standalone_sha1.o: ../../include/openssl/hmac.h
fips_standalone_sha1.o: ../../include/openssl/idea.h
fips_standalone_sha1.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
fips_standalone_sha1.o: ../../include/openssl/md5.h
fips_standalone_sha1.o: ../../include/openssl/mdc2.h
fips_standalone_sha1.o: ../../include/openssl/obj_mac.h
fips_standalone_sha1.o: ../../include/openssl/objects.h
fips_standalone_sha1.o: ../../include/openssl/opensslconf.h
fips_standalone_sha1.o: ../../include/openssl/opensslv.h
fips_standalone_sha1.o: ../../include/openssl/ossl_typ.h
fips_standalone_sha1.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_standalone_sha1.o: ../../include/openssl/rc5.h
fips_standalone_sha1.o: ../../include/openssl/ripemd.h
fips_standalone_sha1.o: ../../include/openssl/rsa.h
fips_standalone_sha1.o: ../../include/openssl/safestack.h
fips_standalone_sha1.o: ../../include/openssl/sha.h
fips_standalone_sha1.o: ../../include/openssl/stack.h
fips_standalone_sha1.o: ../../include/openssl/symhacks.h
fips_standalone_sha1.o: ../../include/openssl/ui.h
fips_standalone_sha1.o: ../../include/openssl/ui_compat.h
fips_standalone_sha1.o: fips_standalone_sha1.c
