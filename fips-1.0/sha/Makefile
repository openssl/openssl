#
# OpenSSL/fips-1.0/sha/Makefile
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
TEST= fips_shatest.c
TESTDATA= SHAmix.req SHAmix.fax
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
	@echo $(LIBOBJ) > lib

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
fips_sha256.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_sha256.o: ../../include/openssl/fips.h ../../include/openssl/fips_sha.h
fips_sha256.o: ../../include/openssl/opensslconf.h
fips_sha256.o: ../../include/openssl/opensslv.h
fips_sha256.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_sha256.o: ../../include/openssl/symhacks.h fips_sha256.c
fips_sha512.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_sha512.o: ../../include/openssl/fips.h ../../include/openssl/fips_sha.h
fips_sha512.o: ../../include/openssl/opensslconf.h
fips_sha512.o: ../../include/openssl/opensslv.h
fips_sha512.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_sha512.o: ../../include/openssl/symhacks.h fips_sha512.c
fips_shatest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_shatest.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
fips_shatest.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
fips_shatest.o: ../../include/openssl/cast.h ../../include/openssl/conf.h
fips_shatest.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fips_shatest.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
fips_shatest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_shatest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_shatest.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
fips_shatest.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
fips_shatest.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
fips_shatest.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_shatest.o: ../../include/openssl/opensslconf.h
fips_shatest.o: ../../include/openssl/opensslv.h
fips_shatest.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
fips_shatest.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
fips_shatest.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
fips_shatest.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
fips_shatest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_shatest.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_shatest.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
fips_shatest.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
fips_shatest.o: fips_shatest.c
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
