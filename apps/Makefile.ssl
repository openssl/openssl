#
#  apps/Makefile.ssl
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES)
CFLAG=		-g -static
INSTALL_PREFIX=
INSTALLTOP=	/usr/local/ssl
OPENSSLDIR=	/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
PERL=		perl
RM=		rm -f
# KRB5 stuff
KRB5_INCLUDES=
LIBKRB5=

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

SHLIB_TARGET=

CFLAGS= -DMONOLITH $(INCLUDES) $(CFLAG)

GENERAL=Makefile makeapps.com install.com

DLIBCRYPTO=../libcrypto.a
DLIBSSL=../libssl.a
LIBCRYPTO=-L.. -lcrypto
LIBSSL=-L.. -lssl

PROGRAM= openssl

SCRIPTS=CA.sh CA.pl der_chop

EXE= $(PROGRAM)$(EXE_EXT)

E_EXE=	verify asn1pars req dgst dh dhparam enc passwd gendh errstr \
	ca crl rsa rsautl dsa dsaparam \
	x509 genrsa gendsa s_server s_client speed \
	s_time version pkcs7 crl2pkcs7 sess_id ciphers nseq pkcs12 \
	pkcs8 spkac smime rand engine ocsp

PROGS= $(PROGRAM).c

A_OBJ=apps.o
A_SRC=apps.c
S_OBJ=	s_cb.o s_socket.o
S_SRC=	s_cb.c s_socket.c
RAND_OBJ=app_rand.o
RAND_SRC=app_rand.c

E_OBJ=	verify.o asn1pars.o req.o dgst.o dh.o dhparam.o enc.o passwd.o gendh.o errstr.o \
	ca.o pkcs7.o crl2p7.o crl.o \
	rsa.o rsautl.o dsa.o dsaparam.o \
	x509.o genrsa.o gendsa.o s_server.o s_client.o speed.o \
	s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) version.o sess_id.o \
	ciphers.o nseq.o pkcs12.o pkcs8.o spkac.o smime.o rand.o engine.o ocsp.o

E_SRC=	verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
	pkcs7.c crl2p7.c crl.c \
	rsa.c rsautl.c dsa.c dsaparam.c \
	x509.c genrsa.c gendsa.c s_server.c s_client.c speed.c \
	s_time.c $(A_SRC) $(S_SRC) $(RAND_SRC) version.c sess_id.c \
	ciphers.c nseq.c pkcs12.c pkcs8.c spkac.c smime.c rand.c engine.c ocsp.c

SRC=$(E_SRC)

EXHEADER=
HEADER=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h \
	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	exe

exe:	$(PROGRAM)

req: sreq.o $(A_OBJ) $(DLIBCRYPTO)
	LD_LIBRARY_PATH=..:$$LD_LIBRARY_PATH \
	$(CC) -o req $(CFLAG) sreq.o $(A_OBJ) $(RAND_OBJ) $(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS)

sreq.o: req.c 
	$(CC) -c $(INCLUDES) $(CFLAG) -o sreq.o req.c

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

install:
	@for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@for i in $(SCRIPTS); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	 done
	@cp openssl.cnf $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	chmod 644 $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	mv -f  $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

tags:
	ctags $(SRC)

tests:

links:
	@sh $(TOP)/util/point.sh Makefile.ssl Makefile

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

$(PROGRAM): progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(PROGRAM)
	if [ "$(SHLIB_TARGET)" = "hpux-shared" -o "$(SHLIB_TARGET)" = "darwin-shared" ] ; then \
	  $(CC) -o $(PROGRAM) $(CFLAGS) $(PROGRAM).o $(E_OBJ) $(PEX_LIBS) $(DLIBSSL) $(LIBKRB5) $(DLIBCRYPTO) $(EX_LIBS) ; \
	else \
	  LD_LIBRARY_PATH=..:$$LD_LIBRARY_PATH \
	  $(CC) -o $(PROGRAM) $(CFLAGS) $(PROGRAM).o $(E_OBJ) $(PEX_LIBS) $(LIBSSL) $(LIBKRB5) $(LIBCRYPTO) $(EX_LIBS) ; \
	fi
	-(cd ..; OPENSSL="`pwd`/apps/openssl"; export OPENSSL; \
		LD_LIBRARY_PATH="`pwd`:$$LD_LIBRARY_PATH"; \
		DYLD_LIBRARY_PATH="`pwd`:$$DYLD_LIBRARY_PATH"; \
		SHLIB_PATH="`pwd`:$$SHLIB_PATH"; \
		LIBPATH="`pwd`:$$LIBPATH"; \
		if [ "$(PLATFORM)" = "Cygwin" ]; then PATH="`pwd`:$$PATH"; fi; \
		export LD_LIBRARY_PATH DYLD_LIBRARY_PATH SHLIB_PATH LIBPATH PATH; \
		$(PERL) tools/c_rehash certs)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM) $(PROGRAM).o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
app_rand.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
app_rand.o: ../include/openssl/bn.h ../include/openssl/buffer.h
app_rand.o: ../include/openssl/cast.h ../include/openssl/conf.h
app_rand.o: ../include/openssl/crypto.h ../include/openssl/des.h
app_rand.o: ../include/openssl/des_old.h ../include/openssl/dh.h
app_rand.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
app_rand.o: ../include/openssl/engine.h ../include/openssl/err.h
app_rand.o: ../include/openssl/evp.h ../include/openssl/idea.h
app_rand.o: ../include/openssl/lhash.h ../include/openssl/md2.h
app_rand.o: ../include/openssl/md4.h ../include/openssl/md5.h
app_rand.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
app_rand.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
app_rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
app_rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
app_rand.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
app_rand.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
app_rand.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
app_rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h app_rand.c
app_rand.o: apps.h
apps.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
apps.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/cast.h ../include/openssl/conf.h
apps.o: ../include/openssl/crypto.h ../include/openssl/des.h
apps.o: ../include/openssl/des_old.h ../include/openssl/dh.h
apps.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
apps.o: ../include/openssl/engine.h ../include/openssl/err.h
apps.o: ../include/openssl/evp.h ../include/openssl/idea.h
apps.o: ../include/openssl/lhash.h ../include/openssl/md2.h
apps.o: ../include/openssl/md4.h ../include/openssl/md5.h
apps.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
apps.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
apps.o: ../include/openssl/pem.h ../include/openssl/pem2.h
apps.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
apps.o: ../include/openssl/rand.h ../include/openssl/rc2.h
apps.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
apps.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
apps.o: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
apps.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
apps.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.c apps.h
asn1pars.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
asn1pars.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
asn1pars.o: ../include/openssl/bn.h ../include/openssl/buffer.h
asn1pars.o: ../include/openssl/cast.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/des.h
asn1pars.o: ../include/openssl/des_old.h ../include/openssl/dh.h
asn1pars.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/engine.h ../include/openssl/err.h
asn1pars.o: ../include/openssl/evp.h ../include/openssl/idea.h
asn1pars.o: ../include/openssl/lhash.h ../include/openssl/md2.h
asn1pars.o: ../include/openssl/md4.h ../include/openssl/md5.h
asn1pars.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
asn1pars.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
asn1pars.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
asn1pars.o: ../include/openssl/pem.h ../include/openssl/pem2.h
asn1pars.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
asn1pars.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
asn1pars.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
asn1pars.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
asn1pars.o: ../include/openssl/sha.h ../include/openssl/stack.h
asn1pars.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
asn1pars.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
asn1pars.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
asn1pars.o: asn1pars.c
ca.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
ca.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/cast.h ../include/openssl/conf.h
ca.o: ../include/openssl/crypto.h ../include/openssl/des.h
ca.o: ../include/openssl/des_old.h ../include/openssl/dh.h
ca.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
ca.o: ../include/openssl/engine.h ../include/openssl/err.h
ca.o: ../include/openssl/evp.h ../include/openssl/idea.h
ca.o: ../include/openssl/lhash.h ../include/openssl/md2.h
ca.o: ../include/openssl/md4.h ../include/openssl/md5.h
ca.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
ca.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ca.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ca.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ca.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ca.o: ../include/openssl/rand.h ../include/openssl/rc2.h
ca.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
ca.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
ca.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ca.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ca.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
ca.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
ca.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ca.c
ciphers.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
ciphers.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
ciphers.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ciphers.o: ../include/openssl/cast.h ../include/openssl/comp.h
ciphers.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ciphers.o: ../include/openssl/des.h ../include/openssl/des_old.h
ciphers.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ciphers.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/idea.h ../include/openssl/kssl.h
ciphers.o: ../include/openssl/lhash.h ../include/openssl/md2.h
ciphers.o: ../include/openssl/md4.h ../include/openssl/md5.h
ciphers.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
ciphers.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ciphers.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ciphers.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
ciphers.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
ciphers.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ciphers.o: ../include/openssl/sha.h ../include/openssl/ssl.h
ciphers.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ciphers.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ciphers.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ciphers.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
ciphers.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
ciphers.o: ../include/openssl/x509_vfy.h apps.h ciphers.c
crl.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
crl.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
crl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
crl.o: ../include/openssl/cast.h ../include/openssl/conf.h
crl.o: ../include/openssl/crypto.h ../include/openssl/des.h
crl.o: ../include/openssl/des_old.h ../include/openssl/dh.h
crl.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/engine.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/idea.h
crl.o: ../include/openssl/lhash.h ../include/openssl/md2.h
crl.o: ../include/openssl/md4.h ../include/openssl/md5.h
crl.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
crl.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
crl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
crl.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
crl.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
crl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
crl.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
crl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl.o: ../include/openssl/x509v3.h apps.h crl.c
crl2p7.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
crl2p7.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
crl2p7.o: ../include/openssl/bn.h ../include/openssl/buffer.h
crl2p7.o: ../include/openssl/cast.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/des.h
crl2p7.o: ../include/openssl/des_old.h ../include/openssl/dh.h
crl2p7.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/engine.h ../include/openssl/err.h
crl2p7.o: ../include/openssl/evp.h ../include/openssl/idea.h
crl2p7.o: ../include/openssl/lhash.h ../include/openssl/md2.h
crl2p7.o: ../include/openssl/md4.h ../include/openssl/md5.h
crl2p7.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
crl2p7.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
crl2p7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl2p7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl2p7.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
crl2p7.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
crl2p7.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
crl2p7.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
crl2p7.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl2p7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl2p7.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
crl2p7.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
crl2p7.o: crl2p7.c
dgst.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
dgst.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
dgst.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dgst.o: ../include/openssl/cast.h ../include/openssl/conf.h
dgst.o: ../include/openssl/crypto.h ../include/openssl/des.h
dgst.o: ../include/openssl/des_old.h ../include/openssl/dh.h
dgst.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/engine.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/idea.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dgst.o: ../include/openssl/md4.h ../include/openssl/md5.h
dgst.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dgst.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dgst.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dgst.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dgst.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dgst.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dgst.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dgst.o: ../include/openssl/sha.h ../include/openssl/stack.h
dgst.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dgst.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
dgst.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h dgst.c
dh.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
dh.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
dh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dh.o: ../include/openssl/cast.h ../include/openssl/conf.h
dh.o: ../include/openssl/crypto.h ../include/openssl/des.h
dh.o: ../include/openssl/des_old.h ../include/openssl/dh.h
dh.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dh.o: ../include/openssl/engine.h ../include/openssl/err.h
dh.o: ../include/openssl/evp.h ../include/openssl/idea.h
dh.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dh.o: ../include/openssl/md4.h ../include/openssl/md5.h
dh.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dh.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dh.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dh.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dh.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dh.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dh.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dh.o: ../include/openssl/sha.h ../include/openssl/stack.h
dh.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dh.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
dh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h dh.c
dsa.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
dsa.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/cast.h ../include/openssl/conf.h
dsa.o: ../include/openssl/crypto.h ../include/openssl/des.h
dsa.o: ../include/openssl/des_old.h ../include/openssl/dh.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/engine.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
dsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
dsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsa.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
dsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h dsa.c
dsaparam.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
dsaparam.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/cast.h ../include/openssl/conf.h
dsaparam.o: ../include/openssl/crypto.h ../include/openssl/des.h
dsaparam.o: ../include/openssl/des_old.h ../include/openssl/dh.h
dsaparam.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsaparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dsaparam.o: ../include/openssl/evp.h ../include/openssl/idea.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dsaparam.o: ../include/openssl/md4.h ../include/openssl/md5.h
dsaparam.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dsaparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsaparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsaparam.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dsaparam.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dsaparam.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dsaparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsaparam.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
dsaparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
dsaparam.o: dsaparam.c
enc.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
enc.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
enc.o: ../include/openssl/bn.h ../include/openssl/buffer.h
enc.o: ../include/openssl/cast.h ../include/openssl/conf.h
enc.o: ../include/openssl/crypto.h ../include/openssl/des.h
enc.o: ../include/openssl/des_old.h ../include/openssl/dh.h
enc.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
enc.o: ../include/openssl/engine.h ../include/openssl/err.h
enc.o: ../include/openssl/evp.h ../include/openssl/idea.h
enc.o: ../include/openssl/lhash.h ../include/openssl/md2.h
enc.o: ../include/openssl/md4.h ../include/openssl/md5.h
enc.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
enc.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
enc.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
enc.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
enc.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
enc.o: ../include/openssl/sha.h ../include/openssl/stack.h
enc.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
enc.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h enc.c
engine.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
engine.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
engine.o: ../include/openssl/bn.h ../include/openssl/buffer.h
engine.o: ../include/openssl/cast.h ../include/openssl/comp.h
engine.o: ../include/openssl/conf.h ../include/openssl/crypto.h
engine.o: ../include/openssl/des.h ../include/openssl/des_old.h
engine.o: ../include/openssl/dh.h ../include/openssl/dsa.h
engine.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
engine.o: ../include/openssl/err.h ../include/openssl/evp.h
engine.o: ../include/openssl/idea.h ../include/openssl/kssl.h
engine.o: ../include/openssl/lhash.h ../include/openssl/md2.h
engine.o: ../include/openssl/md4.h ../include/openssl/md5.h
engine.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
engine.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
engine.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.o: ../include/openssl/pem.h ../include/openssl/pem2.h
engine.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
engine.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
engine.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
engine.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
engine.o: ../include/openssl/sha.h ../include/openssl/ssl.h
engine.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
engine.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
engine.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
engine.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
engine.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
engine.o: ../include/openssl/x509_vfy.h apps.h engine.c
errstr.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
errstr.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
errstr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
errstr.o: ../include/openssl/cast.h ../include/openssl/comp.h
errstr.o: ../include/openssl/conf.h ../include/openssl/crypto.h
errstr.o: ../include/openssl/des.h ../include/openssl/des_old.h
errstr.o: ../include/openssl/dh.h ../include/openssl/dsa.h
errstr.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/idea.h ../include/openssl/kssl.h
errstr.o: ../include/openssl/lhash.h ../include/openssl/md2.h
errstr.o: ../include/openssl/md4.h ../include/openssl/md5.h
errstr.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
errstr.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
errstr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
errstr.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
errstr.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
errstr.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
errstr.o: ../include/openssl/sha.h ../include/openssl/ssl.h
errstr.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
errstr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
errstr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
errstr.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
errstr.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
errstr.o: ../include/openssl/x509_vfy.h apps.h errstr.c
gendh.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
gendh.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
gendh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendh.o: ../include/openssl/cast.h ../include/openssl/conf.h
gendh.o: ../include/openssl/crypto.h ../include/openssl/des.h
gendh.o: ../include/openssl/des_old.h ../include/openssl/dh.h
gendh.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendh.o: ../include/openssl/engine.h ../include/openssl/err.h
gendh.o: ../include/openssl/evp.h ../include/openssl/idea.h
gendh.o: ../include/openssl/lhash.h ../include/openssl/md2.h
gendh.o: ../include/openssl/md4.h ../include/openssl/md5.h
gendh.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
gendh.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
gendh.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendh.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
gendh.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
gendh.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
gendh.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendh.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendh.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendh.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
gendh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h gendh.c
gendsa.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
gendsa.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/cast.h ../include/openssl/conf.h
gendsa.o: ../include/openssl/crypto.h ../include/openssl/des.h
gendsa.o: ../include/openssl/des_old.h ../include/openssl/dh.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/engine.h ../include/openssl/err.h
gendsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
gendsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
gendsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
gendsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
gendsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
gendsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
gendsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
gendsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
gendsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendsa.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
gendsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
gendsa.o: gendsa.c
genrsa.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
genrsa.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
genrsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genrsa.o: ../include/openssl/cast.h ../include/openssl/conf.h
genrsa.o: ../include/openssl/crypto.h ../include/openssl/des.h
genrsa.o: ../include/openssl/des_old.h ../include/openssl/dh.h
genrsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
genrsa.o: ../include/openssl/engine.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
genrsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
genrsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
genrsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
genrsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
genrsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genrsa.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
genrsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
genrsa.o: genrsa.c
nseq.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
nseq.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
nseq.o: ../include/openssl/bn.h ../include/openssl/buffer.h
nseq.o: ../include/openssl/cast.h ../include/openssl/conf.h
nseq.o: ../include/openssl/crypto.h ../include/openssl/des.h
nseq.o: ../include/openssl/des_old.h ../include/openssl/dh.h
nseq.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/engine.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/idea.h
nseq.o: ../include/openssl/lhash.h ../include/openssl/md2.h
nseq.o: ../include/openssl/md4.h ../include/openssl/md5.h
nseq.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
nseq.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
nseq.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
nseq.o: ../include/openssl/pem.h ../include/openssl/pem2.h
nseq.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
nseq.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
nseq.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
nseq.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
nseq.o: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
nseq.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
nseq.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h nseq.c
ocsp.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
ocsp.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
ocsp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.o: ../include/openssl/cast.h ../include/openssl/comp.h
ocsp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ocsp.o: ../include/openssl/des.h ../include/openssl/des_old.h
ocsp.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ocsp.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
ocsp.o: ../include/openssl/err.h ../include/openssl/evp.h
ocsp.o: ../include/openssl/idea.h ../include/openssl/kssl.h
ocsp.o: ../include/openssl/lhash.h ../include/openssl/md2.h
ocsp.o: ../include/openssl/md4.h ../include/openssl/md5.h
ocsp.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
ocsp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ocsp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ocsp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ocsp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ocsp.o: ../include/openssl/rand.h ../include/openssl/rc2.h
ocsp.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
ocsp.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
ocsp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ocsp.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ocsp.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ocsp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ocsp.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ocsp.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
ocsp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ocsp.o: ../include/openssl/x509v3.h apps.h ocsp.c
openssl.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
openssl.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
openssl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
openssl.o: ../include/openssl/cast.h ../include/openssl/comp.h
openssl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.o: ../include/openssl/des.h ../include/openssl/des_old.h
openssl.o: ../include/openssl/dh.h ../include/openssl/dsa.h
openssl.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
openssl.o: ../include/openssl/err.h ../include/openssl/evp.h
openssl.o: ../include/openssl/idea.h ../include/openssl/kssl.h
openssl.o: ../include/openssl/lhash.h ../include/openssl/md2.h
openssl.o: ../include/openssl/md4.h ../include/openssl/md5.h
openssl.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
openssl.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
openssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
openssl.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
openssl.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
openssl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
openssl.o: ../include/openssl/sha.h ../include/openssl/ssl.h
openssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
openssl.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
openssl.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
openssl.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
openssl.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
openssl.o: ../include/openssl/x509_vfy.h apps.h openssl.c progs.h s_apps.h
passwd.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
passwd.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
passwd.o: ../include/openssl/bn.h ../include/openssl/buffer.h
passwd.o: ../include/openssl/cast.h ../include/openssl/conf.h
passwd.o: ../include/openssl/crypto.h ../include/openssl/des.h
passwd.o: ../include/openssl/des_old.h ../include/openssl/dh.h
passwd.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
passwd.o: ../include/openssl/engine.h ../include/openssl/err.h
passwd.o: ../include/openssl/evp.h ../include/openssl/idea.h
passwd.o: ../include/openssl/lhash.h ../include/openssl/md2.h
passwd.o: ../include/openssl/md4.h ../include/openssl/md5.h
passwd.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
passwd.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
passwd.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
passwd.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
passwd.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
passwd.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
passwd.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
passwd.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
passwd.o: passwd.c
pkcs12.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
pkcs12.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
pkcs12.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkcs12.o: ../include/openssl/cast.h ../include/openssl/conf.h
pkcs12.o: ../include/openssl/crypto.h ../include/openssl/des.h
pkcs12.o: ../include/openssl/des_old.h ../include/openssl/dh.h
pkcs12.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/engine.h ../include/openssl/err.h
pkcs12.o: ../include/openssl/evp.h ../include/openssl/idea.h
pkcs12.o: ../include/openssl/lhash.h ../include/openssl/md2.h
pkcs12.o: ../include/openssl/md4.h ../include/openssl/md5.h
pkcs12.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
pkcs12.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pkcs12.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs12.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs12.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs12.o: ../include/openssl/rand.h ../include/openssl/rc2.h
pkcs12.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
pkcs12.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
pkcs12.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs12.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs12.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
pkcs12.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
pkcs12.o: ../include/openssl/x509_vfy.h apps.h pkcs12.c
pkcs7.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
pkcs7.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
pkcs7.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkcs7.o: ../include/openssl/cast.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/des.h
pkcs7.o: ../include/openssl/des_old.h ../include/openssl/dh.h
pkcs7.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/engine.h ../include/openssl/err.h
pkcs7.o: ../include/openssl/evp.h ../include/openssl/idea.h
pkcs7.o: ../include/openssl/lhash.h ../include/openssl/md2.h
pkcs7.o: ../include/openssl/md4.h ../include/openssl/md5.h
pkcs7.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
pkcs7.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pkcs7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs7.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
pkcs7.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
pkcs7.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
pkcs7.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
pkcs7.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs7.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
pkcs7.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h pkcs7.c
pkcs8.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
pkcs8.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
pkcs8.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkcs8.o: ../include/openssl/cast.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/des.h
pkcs8.o: ../include/openssl/des_old.h ../include/openssl/dh.h
pkcs8.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/engine.h ../include/openssl/err.h
pkcs8.o: ../include/openssl/evp.h ../include/openssl/idea.h
pkcs8.o: ../include/openssl/lhash.h ../include/openssl/md2.h
pkcs8.o: ../include/openssl/md4.h ../include/openssl/md5.h
pkcs8.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
pkcs8.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pkcs8.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs8.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs8.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs8.o: ../include/openssl/rand.h ../include/openssl/rc2.h
pkcs8.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
pkcs8.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
pkcs8.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs8.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs8.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
pkcs8.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
pkcs8.o: ../include/openssl/x509_vfy.h apps.h pkcs8.c
rand.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
rand.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
rand.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rand.o: ../include/openssl/cast.h ../include/openssl/conf.h
rand.o: ../include/openssl/crypto.h ../include/openssl/des.h
rand.o: ../include/openssl/des_old.h ../include/openssl/dh.h
rand.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
rand.o: ../include/openssl/engine.h ../include/openssl/err.h
rand.o: ../include/openssl/evp.h ../include/openssl/idea.h
rand.o: ../include/openssl/lhash.h ../include/openssl/md2.h
rand.o: ../include/openssl/md4.h ../include/openssl/md5.h
rand.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
rand.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rand.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
rand.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
rand.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h rand.c
req.o: ../crypto/cryptlib.h ../e_os.h ../include/openssl/aes.h
req.o: ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
req.o: ../include/openssl/buffer.h ../include/openssl/cast.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/des.h ../include/openssl/des_old.h
req.o: ../include/openssl/dh.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
req.o: ../include/openssl/err.h ../include/openssl/evp.h
req.o: ../include/openssl/idea.h ../include/openssl/lhash.h
req.o: ../include/openssl/md2.h ../include/openssl/md4.h
req.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
req.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
req.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
req.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
req.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
req.o: ../include/openssl/rand.h ../include/openssl/rc2.h
req.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
req.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
req.o: ../include/openssl/safestack.h ../include/openssl/sha.h
req.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
req.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
req.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
req.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h req.c
rsa.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
rsa.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/cast.h ../include/openssl/conf.h
rsa.o: ../include/openssl/crypto.h ../include/openssl/des.h
rsa.o: ../include/openssl/des_old.h ../include/openssl/dh.h
rsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
rsa.o: ../include/openssl/engine.h ../include/openssl/err.h
rsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
rsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
rsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
rsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
rsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsa.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
rsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h rsa.c
rsautl.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
rsautl.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
rsautl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsautl.o: ../include/openssl/cast.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/des.h
rsautl.o: ../include/openssl/des_old.h ../include/openssl/dh.h
rsautl.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/engine.h ../include/openssl/err.h
rsautl.o: ../include/openssl/evp.h ../include/openssl/idea.h
rsautl.o: ../include/openssl/lhash.h ../include/openssl/md2.h
rsautl.o: ../include/openssl/md4.h ../include/openssl/md5.h
rsautl.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
rsautl.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rsautl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsautl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsautl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rsautl.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
rsautl.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsautl.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
rsautl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
rsautl.o: rsautl.c
s_cb.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
s_cb.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
s_cb.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_cb.o: ../include/openssl/cast.h ../include/openssl/comp.h
s_cb.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.o: ../include/openssl/des.h ../include/openssl/des_old.h
s_cb.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_cb.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
s_cb.o: ../include/openssl/err.h ../include/openssl/evp.h
s_cb.o: ../include/openssl/idea.h ../include/openssl/kssl.h
s_cb.o: ../include/openssl/lhash.h ../include/openssl/md2.h
s_cb.o: ../include/openssl/md4.h ../include/openssl/md5.h
s_cb.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
s_cb.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_cb.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_cb.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_cb.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_cb.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_cb.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_cb.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_cb.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_cb.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_cb.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_cb.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
s_cb.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
s_cb.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_cb.c
s_client.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
s_client.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
s_client.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_client.o: ../include/openssl/cast.h ../include/openssl/comp.h
s_client.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_client.o: ../include/openssl/des.h ../include/openssl/des_old.h
s_client.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/idea.h ../include/openssl/kssl.h
s_client.o: ../include/openssl/lhash.h ../include/openssl/md2.h
s_client.o: ../include/openssl/md4.h ../include/openssl/md5.h
s_client.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
s_client.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_client.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_client.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_client.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_client.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_client.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_client.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_client.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_client.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_client.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
s_client.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
s_client.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_client.c
s_server.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
s_server.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
s_server.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_server.o: ../include/openssl/cast.h ../include/openssl/comp.h
s_server.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_server.o: ../include/openssl/des.h ../include/openssl/des_old.h
s_server.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_server.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
s_server.o: ../include/openssl/err.h ../include/openssl/evp.h
s_server.o: ../include/openssl/idea.h ../include/openssl/kssl.h
s_server.o: ../include/openssl/lhash.h ../include/openssl/md2.h
s_server.o: ../include/openssl/md4.h ../include/openssl/md5.h
s_server.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
s_server.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_server.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_server.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_server.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_server.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_server.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_server.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_server.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_server.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
s_server.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
s_server.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_server.c
s_socket.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
s_socket.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
s_socket.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_socket.o: ../include/openssl/cast.h ../include/openssl/comp.h
s_socket.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_socket.o: ../include/openssl/des.h ../include/openssl/des_old.h
s_socket.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_socket.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
s_socket.o: ../include/openssl/err.h ../include/openssl/evp.h
s_socket.o: ../include/openssl/idea.h ../include/openssl/kssl.h
s_socket.o: ../include/openssl/lhash.h ../include/openssl/md2.h
s_socket.o: ../include/openssl/md4.h ../include/openssl/md5.h
s_socket.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
s_socket.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_socket.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_socket.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_socket.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_socket.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_socket.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_socket.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
s_socket.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
s_socket.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
s_time.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
s_time.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_time.o: ../include/openssl/cast.h ../include/openssl/comp.h
s_time.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_time.o: ../include/openssl/des.h ../include/openssl/des_old.h
s_time.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_time.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/idea.h ../include/openssl/kssl.h
s_time.o: ../include/openssl/lhash.h ../include/openssl/md2.h
s_time.o: ../include/openssl/md4.h ../include/openssl/md5.h
s_time.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
s_time.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_time.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_time.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_time.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_time.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_time.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_time.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_time.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_time.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_time.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
s_time.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
s_time.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
sess_id.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
sess_id.o: ../include/openssl/bn.h ../include/openssl/buffer.h
sess_id.o: ../include/openssl/cast.h ../include/openssl/comp.h
sess_id.o: ../include/openssl/conf.h ../include/openssl/crypto.h
sess_id.o: ../include/openssl/des.h ../include/openssl/des_old.h
sess_id.o: ../include/openssl/dh.h ../include/openssl/dsa.h
sess_id.o: ../include/openssl/e_os2.h ../include/openssl/engine.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/idea.h ../include/openssl/kssl.h
sess_id.o: ../include/openssl/lhash.h ../include/openssl/md2.h
sess_id.o: ../include/openssl/md4.h ../include/openssl/md5.h
sess_id.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
sess_id.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
sess_id.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
sess_id.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
sess_id.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
sess_id.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
sess_id.o: ../include/openssl/sha.h ../include/openssl/ssl.h
sess_id.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
sess_id.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sess_id.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sess_id.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
sess_id.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
sess_id.o: ../include/openssl/x509_vfy.h apps.h sess_id.c
smime.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
smime.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
smime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
smime.o: ../include/openssl/cast.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/des.h
smime.o: ../include/openssl/des_old.h ../include/openssl/dh.h
smime.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/engine.h ../include/openssl/err.h
smime.o: ../include/openssl/evp.h ../include/openssl/idea.h
smime.o: ../include/openssl/lhash.h ../include/openssl/md2.h
smime.o: ../include/openssl/md4.h ../include/openssl/md5.h
smime.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
smime.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
smime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
smime.o: ../include/openssl/pem.h ../include/openssl/pem2.h
smime.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
smime.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
smime.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
smime.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
smime.o: ../include/openssl/sha.h ../include/openssl/stack.h
smime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
smime.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
smime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h smime.c
speed.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
speed.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
speed.o: ../include/openssl/bn.h ../include/openssl/buffer.h
speed.o: ../include/openssl/cast.h ../include/openssl/conf.h
speed.o: ../include/openssl/crypto.h ../include/openssl/des.h
speed.o: ../include/openssl/des_old.h ../include/openssl/dh.h
speed.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
speed.o: ../include/openssl/engine.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.o: ../include/openssl/idea.h ../include/openssl/lhash.h
speed.o: ../include/openssl/md2.h ../include/openssl/md4.h
speed.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
speed.o: ../include/openssl/rand.h ../include/openssl/rc2.h
speed.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
speed.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
speed.o: ../include/openssl/safestack.h ../include/openssl/sha.h
speed.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
speed.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
speed.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
speed.o: ../include/openssl/x509_vfy.h apps.h speed.c testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
spkac.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
spkac.o: ../include/openssl/bn.h ../include/openssl/buffer.h
spkac.o: ../include/openssl/cast.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/des.h
spkac.o: ../include/openssl/des_old.h ../include/openssl/dh.h
spkac.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/engine.h ../include/openssl/err.h
spkac.o: ../include/openssl/evp.h ../include/openssl/idea.h
spkac.o: ../include/openssl/lhash.h ../include/openssl/md2.h
spkac.o: ../include/openssl/md4.h ../include/openssl/md5.h
spkac.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
spkac.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
spkac.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
spkac.o: ../include/openssl/pem.h ../include/openssl/pem2.h
spkac.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
spkac.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
spkac.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
spkac.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
spkac.o: ../include/openssl/sha.h ../include/openssl/stack.h
spkac.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
spkac.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
spkac.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h spkac.c
verify.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
verify.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
verify.o: ../include/openssl/bn.h ../include/openssl/buffer.h
verify.o: ../include/openssl/cast.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/des.h
verify.o: ../include/openssl/des_old.h ../include/openssl/dh.h
verify.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/engine.h ../include/openssl/err.h
verify.o: ../include/openssl/evp.h ../include/openssl/idea.h
verify.o: ../include/openssl/lhash.h ../include/openssl/md2.h
verify.o: ../include/openssl/md4.h ../include/openssl/md5.h
verify.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
verify.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
verify.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
verify.o: ../include/openssl/pem.h ../include/openssl/pem2.h
verify.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
verify.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
verify.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
verify.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
verify.o: ../include/openssl/sha.h ../include/openssl/stack.h
verify.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
verify.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
verify.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
verify.o: ../include/openssl/x509v3.h apps.h verify.c
version.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
version.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
version.o: ../include/openssl/bn.h ../include/openssl/buffer.h
version.o: ../include/openssl/cast.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/des_old.h ../include/openssl/dh.h
version.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
version.o: ../include/openssl/engine.h ../include/openssl/err.h
version.o: ../include/openssl/evp.h ../include/openssl/idea.h
version.o: ../include/openssl/lhash.h ../include/openssl/md2.h
version.o: ../include/openssl/md4.h ../include/openssl/md5.h
version.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
version.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
version.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
version.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
version.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
version.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
version.o: ../include/openssl/sha.h ../include/openssl/stack.h
version.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
version.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
version.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
version.o: version.c
x509.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
x509.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/cast.h ../include/openssl/conf.h
x509.o: ../include/openssl/crypto.h ../include/openssl/des.h
x509.o: ../include/openssl/des_old.h ../include/openssl/dh.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/engine.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/idea.h
x509.o: ../include/openssl/lhash.h ../include/openssl/md2.h
x509.o: ../include/openssl/md4.h ../include/openssl/md5.h
x509.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
x509.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
x509.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
x509.o: ../include/openssl/pem.h ../include/openssl/pem2.h
x509.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
x509.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
x509.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
x509.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
x509.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
x509.o: ../include/openssl/x509v3.h apps.h x509.c
