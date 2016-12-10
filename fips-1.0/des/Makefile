#
# OpenSSL/fips-1.0/des/Makefile
#

DIR=	des
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

FIPS_DES_ENC=fips_des_enc.o

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_desmovs.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_des_enc.c asm/fips-dx86-elf.s fips_des_selftest.c fips_set_key.c
LIBOBJ=$(FIPS_DES_ENC) fips_des_selftest.o fips_set_key.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER) fips_des_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

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

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) \
		$(SRC) $(TEST)
dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
# DO NOT DELETE THIS LINE -- make depend depends on it.

fips_des_enc.o: ../../e_os.h ../../include/openssl/crypto.h
fips_des_enc.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
fips_des_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/fips.h
fips_des_enc.o: ../../include/openssl/opensslconf.h
fips_des_enc.o: ../../include/openssl/opensslv.h
fips_des_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_des_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_des_enc.o: ../../include/openssl/ui_compat.h fips_des_enc.c
fips_des_enc.o: fips_des_locl.h
fips_des_selftest.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_des_selftest.o: ../../include/openssl/des.h
fips_des_selftest.o: ../../include/openssl/des_old.h
fips_des_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_des_selftest.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_des_selftest.o: ../../include/openssl/opensslconf.h
fips_des_selftest.o: ../../include/openssl/opensslv.h
fips_des_selftest.o: ../../include/openssl/safestack.h
fips_des_selftest.o: ../../include/openssl/stack.h
fips_des_selftest.o: ../../include/openssl/symhacks.h
fips_des_selftest.o: ../../include/openssl/ui.h
fips_des_selftest.o: ../../include/openssl/ui_compat.h fips_des_selftest.c
fips_desmovs.o: ../../e_os.h ../../include/openssl/aes.h
fips_desmovs.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_desmovs.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
fips_desmovs.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
fips_desmovs.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
fips_desmovs.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
fips_desmovs.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_desmovs.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_desmovs.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
fips_desmovs.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
fips_desmovs.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
fips_desmovs.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_desmovs.o: ../../include/openssl/opensslconf.h
fips_desmovs.o: ../../include/openssl/opensslv.h
fips_desmovs.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rc2.h
fips_desmovs.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
fips_desmovs.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
fips_desmovs.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
fips_desmovs.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_desmovs.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
fips_desmovs.o: fips_desmovs.c
fips_set_key.o: ../../e_os.h ../../include/openssl/crypto.h
fips_set_key.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
fips_set_key.o: ../../include/openssl/e_os2.h ../../include/openssl/fips.h
fips_set_key.o: ../../include/openssl/opensslconf.h
fips_set_key.o: ../../include/openssl/opensslv.h
fips_set_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_set_key.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fips_set_key.o: ../../include/openssl/ui_compat.h fips_des_locl.h
fips_set_key.o: fips_set_key.c
