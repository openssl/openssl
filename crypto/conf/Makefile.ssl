#
# SSLeay/crypto/conf/Makefile
#

DIR=	conf
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= conf_err.c conf_lib.c conf_api.c conf_def.c conf_mod.c \
	 conf_mall.c conf_sap.c

LIBOBJ=	conf_err.o conf_lib.o conf_api.o conf_def.o conf_mod.o \
	conf_mall.o conf_sap.o

SRC= $(LIBSRC)

EXHEADER= conf.h conf_api.h
HEADER=	conf_def.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@sh $(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

conf_api.o: ../../e_os.h ../../include/openssl/bio.h
conf_api.o: ../../include/openssl/conf.h ../../include/openssl/conf_api.h
conf_api.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
conf_api.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
conf_api.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_api.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_api.o: conf_api.c
conf_def.o: ../../e_os.h ../../include/openssl/bio.h
conf_def.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
conf_def.o: ../../include/openssl/conf_api.h ../../include/openssl/crypto.h
conf_def.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
conf_def.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
conf_def.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_def.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_def.o: ../cryptlib.h conf_def.c conf_def.h
conf_err.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
conf_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
conf_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
conf_err.o: ../../include/openssl/opensslconf.h
conf_err.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_err.o: conf_err.c
conf_lib.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
conf_lib.o: ../../include/openssl/conf_api.h ../../include/openssl/crypto.h
conf_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
conf_lib.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
conf_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_lib.o: conf_lib.c
conf_mall.o: ../../e_os.h ../../include/openssl/aes.h
conf_mall.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
conf_mall.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
conf_mall.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
conf_mall.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
conf_mall.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
conf_mall.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
conf_mall.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
conf_mall.o: ../../include/openssl/engine.h ../../include/openssl/err.h
conf_mall.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
conf_mall.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
conf_mall.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
conf_mall.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
conf_mall.o: ../../include/openssl/objects.h
conf_mall.o: ../../include/openssl/opensslconf.h
conf_mall.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
conf_mall.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
conf_mall.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
conf_mall.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
conf_mall.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
conf_mall.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
conf_mall.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
conf_mall.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
conf_mall.o: ../../include/openssl/x509_vfy.h ../cryptlib.h conf_mall.c
conf_mod.o: ../../e_os.h ../../include/openssl/aes.h
conf_mod.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
conf_mod.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
conf_mod.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
conf_mod.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
conf_mod.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
conf_mod.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
conf_mod.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
conf_mod.o: ../../include/openssl/err.h ../../include/openssl/evp.h
conf_mod.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
conf_mod.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
conf_mod.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
conf_mod.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
conf_mod.o: ../../include/openssl/opensslconf.h
conf_mod.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
conf_mod.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
conf_mod.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
conf_mod.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
conf_mod.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
conf_mod.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_mod.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
conf_mod.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
conf_mod.o: ../cryptlib.h conf_mod.c
conf_sap.o: ../../e_os.h ../../include/openssl/aes.h
conf_sap.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
conf_sap.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
conf_sap.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
conf_sap.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
conf_sap.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
conf_sap.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
conf_sap.o: ../../include/openssl/dso.h ../../include/openssl/e_os2.h
conf_sap.o: ../../include/openssl/engine.h ../../include/openssl/err.h
conf_sap.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
conf_sap.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
conf_sap.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
conf_sap.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
conf_sap.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
conf_sap.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
conf_sap.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
conf_sap.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
conf_sap.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
conf_sap.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
conf_sap.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
conf_sap.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
conf_sap.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
conf_sap.o: ../../include/openssl/x509_vfy.h ../cryptlib.h conf_sap.c
