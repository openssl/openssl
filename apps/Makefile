#
#  apps/Makefile
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES)
CFLAG=		-g -static
MAKEFILE=	Makefile
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

SCRIPTS=CA.sh CA.pl tsget

EXE= $(PROGRAM)$(EXE_EXT)

E_EXE=	verify asn1pars req dgst dh dhparam enc passwd gendh errstr \
	ca crl rsa rsautl dsa dsaparam ec ecparam \
	x509 genrsa gendsa genpkey s_server s_client speed \
	s_time version pkcs7 cms crl2pkcs7 sess_id ciphers nseq pkcs12 \
	pkcs8 pkey pkeyparam pkeyutl spkac smime rand engine ocsp prime ts srp

PROGS= $(PROGRAM).c

A_OBJ=apps.o
A_SRC=apps.c
S_OBJ=	s_cb.o s_socket.o
S_SRC=	s_cb.c s_socket.c
RAND_OBJ=app_rand.o
RAND_SRC=app_rand.c

E_OBJ=	verify.o asn1pars.o req.o dgst.o dh.o dhparam.o enc.o passwd.o gendh.o errstr.o \
	ca.o pkcs7.o crl2p7.o crl.o \
	rsa.o rsautl.o dsa.o dsaparam.o ec.o ecparam.o \
	x509.o genrsa.o gendsa.o genpkey.o s_server.o s_client.o speed.o \
	s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) version.o sess_id.o \
	ciphers.o nseq.o pkcs12.o pkcs8.o pkey.o pkeyparam.o pkeyutl.o \
	spkac.o smime.o cms.o rand.o engine.o ocsp.o prime.o ts.o srp.o

E_SRC=	verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
	pkcs7.c crl2p7.c crl.c \
	rsa.c rsautl.c dsa.c dsaparam.c ec.c ecparam.c \
	x509.c genrsa.c gendsa.c genpkey.c s_server.c s_client.c speed.c \
	s_time.c $(A_SRC) $(S_SRC) $(RAND_SRC) version.c sess_id.c \
	ciphers.c nseq.c pkcs12.c pkcs8.c pkey.c pkeyparam.c pkeyutl.c \
	spkac.c smime.c cms.c rand.c engine.c ocsp.c prime.c ts.c srp.c

SRC=$(E_SRC)

EXHEADER=
HEADER=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h \
	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	exe

exe:	$(EXE)

req: sreq.o $(A_OBJ) $(DLIBCRYPTO)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=req OBJECTS="sreq.o $(A_OBJ) $(RAND_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS)" \
		link_app.$${shlib_target}

sreq.o: req.c 
	$(CC) -c $(INCLUDES) $(CFLAG) -o sreq.o req.c

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@set -e; for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@set -e; for i in $(SCRIPTS); \
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

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f CA.pl

clean:
	rm -f *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

$(EXE): progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(EXE)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	elif [ -n "$(FIPSCANLIB)" ]; then \
	  FIPSLD_CC="$(CC)"; CC=$(FIPSDIR)/bin/fipsld; export CC FIPSLD_CC; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBKRB5) $(LIBCRYPTO)" ; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$(EXE) OBJECTS="$(PROGRAM).o $(E_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM) $(PROGRAM).o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
app_rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
app_rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
app_rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
app_rand.o: ../include/openssl/ecdsa.h ../include/openssl/evp.h
app_rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
app_rand.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
app_rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
app_rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
app_rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
app_rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
app_rand.o: ../include/openssl/x509v3.h app_rand.c apps.h
apps.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.o: ../include/openssl/err.h ../include/openssl/evp.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
apps.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
apps.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
apps.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
apps.o: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
apps.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
apps.o: ../include/openssl/x509v3.h apps.c apps.h
asn1pars.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
asn1pars.o: ../include/openssl/evp.h ../include/openssl/lhash.h
asn1pars.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
asn1pars.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
asn1pars.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
asn1pars.o: ../include/openssl/pem.h ../include/openssl/pem2.h
asn1pars.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
asn1pars.o: ../include/openssl/sha.h ../include/openssl/stack.h
asn1pars.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
asn1pars.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
asn1pars.o: ../include/openssl/x509v3.h apps.h asn1pars.c
ca.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.o: ../include/openssl/err.h ../include/openssl/evp.h
ca.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ca.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ca.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ca.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ca.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ca.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ca.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ca.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ca.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ca.c
ciphers.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ciphers.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ciphers.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ciphers.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ciphers.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ciphers.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ciphers.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ciphers.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ciphers.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ciphers.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ciphers.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ciphers.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ciphers.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ciphers.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ciphers.o: ../include/openssl/x509v3.h apps.h ciphers.c
cms.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
cms.o: ../include/openssl/buffer.h ../include/openssl/conf.h
cms.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
cms.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
cms.o: ../include/openssl/ecdsa.h ../include/openssl/evp.h
cms.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
cms.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
cms.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cms.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
cms.o: ../include/openssl/safestack.h ../include/openssl/sha.h
cms.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
cms.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
cms.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h cms.c
crl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl.o: ../include/openssl/x509v3.h apps.h crl.c
crl2p7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl2p7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl2p7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl2p7.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl2p7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl2p7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl2p7.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl2p7.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl2p7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl2p7.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl2p7.o: ../include/openssl/x509v3.h apps.h crl2p7.c
dgst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dgst.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/hmac.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dgst.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dgst.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dgst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dgst.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dgst.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dgst.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dgst.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h dgst.c
dh.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dh.o: ../include/openssl/dh.h ../include/openssl/e_os2.h
dh.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dh.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dh.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dh.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dh.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dh.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dh.o: ../include/openssl/sha.h ../include/openssl/stack.h
dh.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dh.o: ../include/openssl/x509v3.h apps.h dh.c
dsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsa.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsa.o: ../include/openssl/x509v3.h apps.h dsa.c
dsaparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dsaparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsaparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dsaparam.o: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsaparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsaparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsaparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsaparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsaparam.o: ../include/openssl/x509v3.h apps.h dsaparam.c
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ec.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ec.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ec.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ec.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ec.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ec.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ec.o: ../include/openssl/sha.h ../include/openssl/stack.h
ec.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ec.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ec.o: ../include/openssl/x509v3.h apps.h ec.c
ecparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/err.h ../include/openssl/evp.h
ecparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ecparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ecparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ecparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ecparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ecparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ecparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ecparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ecparam.o: ecparam.c
enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
enc.o: ../include/openssl/buffer.h ../include/openssl/comp.h
enc.o: ../include/openssl/conf.h ../include/openssl/crypto.h
enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enc.o: ../include/openssl/err.h ../include/openssl/evp.h
enc.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
enc.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enc.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.o: ../include/openssl/rand.h ../include/openssl/safestack.h
enc.o: ../include/openssl/sha.h ../include/openssl/stack.h
enc.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
enc.o: ../include/openssl/x509v3.h apps.h enc.c
engine.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/buffer.h ../include/openssl/conf.h
engine.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
engine.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
engine.o: ../include/openssl/evp.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
engine.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
engine.o: ../include/openssl/sha.h ../include/openssl/stack.h
engine.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
engine.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
engine.o: ../include/openssl/x509v3.h apps.h engine.c
errstr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/buffer.h ../include/openssl/comp.h
errstr.o: ../include/openssl/conf.h ../include/openssl/crypto.h
errstr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
errstr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
errstr.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
errstr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
errstr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
errstr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
errstr.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
errstr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
errstr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
errstr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
errstr.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
errstr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
errstr.o: ../include/openssl/x509v3.h apps.h errstr.c
gendh.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendh.o: ../include/openssl/dh.h ../include/openssl/dsa.h
gendh.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
gendh.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
gendh.o: ../include/openssl/err.h ../include/openssl/evp.h
gendh.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
gendh.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
gendh.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendh.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendh.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendh.o: ../include/openssl/rand.h ../include/openssl/rsa.h
gendh.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendh.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendh.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
gendh.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
gendh.o: gendh.c
gendsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
gendsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
gendsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendsa.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
gendsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
gendsa.o: ../include/openssl/x509v3.h apps.h gendsa.c
genpkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genpkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
genpkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
genpkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genpkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genpkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genpkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genpkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genpkey.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
genpkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
genpkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genpkey.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genpkey.o: ../include/openssl/x509v3.h apps.h genpkey.c
genrsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genrsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genrsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genrsa.o: ../include/openssl/dh.h ../include/openssl/dsa.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
genrsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
genrsa.o: ../include/openssl/err.h ../include/openssl/evp.h
genrsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
genrsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
genrsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
genrsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
genrsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genrsa.o: ../include/openssl/rand.h ../include/openssl/rsa.h
genrsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
genrsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
genrsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
genrsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
genrsa.o: genrsa.c
nseq.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/buffer.h ../include/openssl/conf.h
nseq.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/lhash.h
nseq.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
nseq.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
nseq.o: ../include/openssl/pem.h ../include/openssl/pem2.h
nseq.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
nseq.o: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
nseq.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
nseq.o: ../include/openssl/x509v3.h apps.h nseq.c
ocsp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ocsp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.o: ../include/openssl/comp.h ../include/openssl/conf.h
ocsp.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ocsp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ocsp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ocsp.o: ../include/openssl/err.h ../include/openssl/evp.h
ocsp.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ocsp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ocsp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ocsp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ocsp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ocsp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ocsp.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ocsp.o: ../include/openssl/sha.h ../include/openssl/ssl.h
ocsp.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ocsp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ocsp.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ocsp.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ocsp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ocsp.c
openssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
openssl.o: ../include/openssl/buffer.h ../include/openssl/comp.h
openssl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
openssl.o: ../include/openssl/evp.h ../include/openssl/hmac.h
openssl.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
openssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
openssl.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
openssl.o: ../include/openssl/x509v3.h apps.h openssl.c progs.h s_apps.h
passwd.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
passwd.o: ../include/openssl/buffer.h ../include/openssl/conf.h
passwd.o: ../include/openssl/crypto.h ../include/openssl/des.h
passwd.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
passwd.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
passwd.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
passwd.o: ../include/openssl/evp.h ../include/openssl/lhash.h
passwd.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
passwd.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
passwd.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
passwd.o: ../include/openssl/rand.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
passwd.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
passwd.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
passwd.o: ../include/openssl/x509v3.h apps.h passwd.c
pkcs12.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs12.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs12.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs12.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs12.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs12.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs12.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs12.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs12.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs12.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs12.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs12.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs12.o: pkcs12.c
pkcs7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs7.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs7.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs7.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs7.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs7.o: ../include/openssl/x509v3.h apps.h pkcs7.c
pkcs8.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs8.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs8.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs8.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs8.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs8.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs8.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs8.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs8.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs8.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs8.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs8.o: pkcs8.c
pkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkey.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkey.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkey.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkey.o: ../include/openssl/x509v3.h apps.h pkey.c
pkeyparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyparam.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkeyparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkeyparam.o: ../include/openssl/x509v3.h apps.h pkeyparam.c
pkeyutl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyutl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyutl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyutl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyutl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyutl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyutl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyutl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyutl.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkeyutl.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyutl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyutl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkeyutl.o: ../include/openssl/x509v3.h apps.h pkeyutl.c
prime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
prime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
prime.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
prime.o: ../include/openssl/sha.h ../include/openssl/stack.h
prime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
prime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
prime.o: ../include/openssl/x509v3.h apps.h prime.c
rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rand.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rand.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rand.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rand.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rand.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h rand.c
req.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/bn.h ../include/openssl/buffer.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/dh.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
req.o: ../include/openssl/err.h ../include/openssl/evp.h
req.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
req.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
req.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
req.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
req.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
req.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.o: ../include/openssl/sha.h ../include/openssl/stack.h
req.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
req.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
req.o: ../include/openssl/x509v3.h apps.h req.c
rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.o: ../include/openssl/err.h ../include/openssl/evp.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsa.o: ../include/openssl/x509v3.h apps.h rsa.c
rsautl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rsautl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsautl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsautl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsautl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsautl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsautl.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsautl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rsautl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsautl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rsautl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rsautl.o: rsautl.c
s_cb.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_cb.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_cb.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_cb.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_cb.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s_cb.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_cb.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_cb.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_cb.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_cb.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_cb.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_cb.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_cb.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_cb.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_cb.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_cb.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_cb.o: s_apps.h s_cb.c
s_client.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_client.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_client.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_client.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_client.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_client.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_client.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_client.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_client.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_client.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_client.o: ../include/openssl/srp.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_client.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_client.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_client.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_client.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_client.o: s_apps.h s_client.c timeouts.h
s_server.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_server.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_server.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_server.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_server.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_server.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_server.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_server.o: ../include/openssl/err.h ../include/openssl/evp.h
s_server.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_server.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_server.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_server.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_server.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_server.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_server.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_server.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_server.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_server.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_server.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_server.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_server.o: ../include/openssl/x509v3.h apps.h s_apps.h s_server.c timeouts.h
s_socket.o: ../e_os.h ../e_os2.h ../include/openssl/asn1.h
s_socket.o: ../include/openssl/bio.h ../include/openssl/buffer.h
s_socket.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_socket.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_socket.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_socket.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_socket.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_socket.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_socket.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_socket.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_socket.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_socket.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_socket.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_socket.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_socket.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_socket.o: ../include/openssl/x509v3.h apps.h s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_time.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_time.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_time.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_time.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s_time.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_time.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_time.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_time.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_time.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_time.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_time.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_time.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_time.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_time.o: ../include/openssl/x509v3.h apps.h s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/buffer.h ../include/openssl/comp.h
sess_id.o: ../include/openssl/conf.h ../include/openssl/crypto.h
sess_id.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
sess_id.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
sess_id.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
sess_id.o: ../include/openssl/evp.h ../include/openssl/hmac.h
sess_id.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
sess_id.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sess_id.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
sess_id.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
sess_id.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
sess_id.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
sess_id.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
sess_id.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
sess_id.o: ../include/openssl/x509v3.h apps.h sess_id.c
smime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
smime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
smime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
smime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
smime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
smime.o: ../include/openssl/pem.h ../include/openssl/pem2.h
smime.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
smime.o: ../include/openssl/sha.h ../include/openssl/stack.h
smime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
smime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
smime.o: ../include/openssl/x509v3.h apps.h smime.c
speed.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
speed.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
speed.o: ../include/openssl/bn.h ../include/openssl/buffer.h
speed.o: ../include/openssl/conf.h ../include/openssl/crypto.h
speed.o: ../include/openssl/des.h ../include/openssl/des_old.h
speed.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
speed.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
speed.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.o: ../include/openssl/lhash.h ../include/openssl/md4.h
speed.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
speed.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
speed.o: ../include/openssl/rand.h ../include/openssl/rc4.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/sha.h ../include/openssl/stack.h
speed.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
speed.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
speed.o: ../include/openssl/whrlpool.h ../include/openssl/x509.h
speed.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
speed.o: speed.c testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
spkac.o: ../include/openssl/evp.h ../include/openssl/lhash.h
spkac.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
spkac.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
spkac.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
spkac.o: ../include/openssl/pem.h ../include/openssl/pem2.h
spkac.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
spkac.o: ../include/openssl/sha.h ../include/openssl/stack.h
spkac.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
spkac.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
spkac.o: ../include/openssl/x509v3.h apps.h spkac.c
srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
srp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
srp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
srp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
srp.o: ../include/openssl/err.h ../include/openssl/evp.h
srp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
srp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
srp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
srp.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
srp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
srp.o: ../include/openssl/srp.h ../include/openssl/stack.h
srp.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
srp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
srp.o: ../include/openssl/x509v3.h apps.h srp.c
ts.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ts.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ts.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ts.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ts.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ts.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ts.o: ../include/openssl/err.h ../include/openssl/evp.h
ts.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ts.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ts.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ts.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ts.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ts.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ts.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ts.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ts.o: ../include/openssl/ts.h ../include/openssl/txt_db.h
ts.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ts.o: ../include/openssl/x509v3.h apps.h ts.c
verify.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
verify.o: ../include/openssl/evp.h ../include/openssl/lhash.h
verify.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
verify.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
verify.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
verify.o: ../include/openssl/pem.h ../include/openssl/pem2.h
verify.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
verify.o: ../include/openssl/sha.h ../include/openssl/stack.h
verify.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
verify.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
verify.o: ../include/openssl/x509v3.h apps.h verify.c
version.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
version.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
version.o: ../include/openssl/ecdsa.h ../include/openssl/evp.h
version.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
version.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
version.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
version.o: ../include/openssl/rc4.h ../include/openssl/safestack.h
version.o: ../include/openssl/sha.h ../include/openssl/stack.h
version.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
version.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
version.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
version.o: ../include/openssl/x509v3.h apps.h version.c
x509.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/lhash.h
x509.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
x509.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
x509.o: ../include/openssl/pem.h ../include/openssl/pem2.h
x509.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
x509.o: ../include/openssl/safestack.h ../include/openssl/sha.h
x509.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
x509.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
x509.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h x509.c
