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

SCRIPTS=CA.sh CA.pl

EXE= $(PROGRAM)$(EXE_EXT)

E_EXE=	verify asn1pars req dgst dh dhparam enc passwd gendh errstr \
	ca crl rsa rsautl dsa dsaparam ec ecparam \
	x509 genrsa gendsa s_server s_client speed \
	s_time version pkcs7 crl2pkcs7 sess_id ciphers nseq pkcs12 \
	pkcs8 spkac smime rand engine ocsp prime

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
	x509.o genrsa.o gendsa.o s_server.o s_client.o speed.o \
	s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) version.o sess_id.o \
	ciphers.o nseq.o pkcs12.o pkcs8.o spkac.o smime.o rand.o engine.o \
	ocsp.o prime.o

E_SRC=	verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
	pkcs7.c crl2p7.c crl.c \
	rsa.c rsautl.c dsa.c dsaparam.c ec.c ecparam.c \
	x509.c genrsa.c gendsa.c s_server.c s_client.c speed.c \
	s_time.c $(A_SRC) $(S_SRC) $(RAND_SRC) version.c sess_id.c \
	ciphers.c nseq.c pkcs12.c pkcs8.c spkac.c smime.c rand.c engine.c \
	ocsp.c prime.c

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

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
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
	  FIPSLD_CC=$(CC); CC=$(TOP)/fips-1.0/fipsld; export CC FIPSLD_CC; \
	fi; \
	if [ "$${shlib_target}" = "darwin-shared" ] ; then \
	  LIBRARIES="$(DLIBSSL) $(LIBKRB5) $(DLIBCRYPTO)" ; \
	else \
	  LIBRARIES="$(LIBSSL) $(LIBKRB5) $(LIBCRYPTO)" ; \
	fi; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		CC=$${CC} APPNAME=$(EXE) OBJECTS="$(PROGRAM).o $(E_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	-(cd ..; \
	  OPENSSL="`pwd`/util/opensslwrap.sh"; export OPENSSL; \
	  $(PERL) tools/c_rehash certs)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM) $(PROGRAM).o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
app_rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
app_rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
app_rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
app_rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
app_rand.o: ../include/openssl/evp.h ../include/openssl/fips.h
app_rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
app_rand.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
app_rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
app_rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
app_rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
app_rand.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
app_rand.o: ../include/openssl/x509_vfy.h app_rand.c apps.h
apps.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.o: ../include/openssl/engine.h ../include/openssl/err.h
apps.o: ../include/openssl/evp.h ../include/openssl/fips.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
apps.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
apps.o: ../include/openssl/pem.h ../include/openssl/pem2.h
apps.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
apps.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
apps.o: ../include/openssl/sha.h ../include/openssl/stack.h
apps.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
apps.o: ../include/openssl/ui.h ../include/openssl/x509.h
apps.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.c apps.h
asn1pars.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
asn1pars.o: ../include/openssl/err.h ../include/openssl/evp.h
asn1pars.o: ../include/openssl/fips.h ../include/openssl/lhash.h
asn1pars.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
asn1pars.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
asn1pars.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
asn1pars.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
asn1pars.o: ../include/openssl/safestack.h ../include/openssl/sha.h
asn1pars.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
asn1pars.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
asn1pars.o: ../include/openssl/x509_vfy.h apps.h asn1pars.c
ca.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.o: ../include/openssl/engine.h ../include/openssl/err.h
ca.o: ../include/openssl/evp.h ../include/openssl/fips.h
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
ciphers.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ciphers.o: ../include/openssl/comp.h ../include/openssl/conf.h
ciphers.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ciphers.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ciphers.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ciphers.o: ../include/openssl/engine.h ../include/openssl/err.h
ciphers.o: ../include/openssl/evp.h ../include/openssl/fips.h
ciphers.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ciphers.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ciphers.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ciphers.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ciphers.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ciphers.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
ciphers.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ciphers.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ciphers.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ciphers.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
ciphers.o: ciphers.c
crl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl.o: ../include/openssl/err.h ../include/openssl/evp.h
crl.o: ../include/openssl/fips.h ../include/openssl/lhash.h
crl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h crl.c
crl2p7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl2p7.o: ../include/openssl/err.h ../include/openssl/evp.h
crl2p7.o: ../include/openssl/fips.h ../include/openssl/lhash.h
crl2p7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl2p7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl2p7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl2p7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl2p7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl2p7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl2p7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl2p7.o: ../include/openssl/x509_vfy.h apps.h crl2p7.c
dgst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dgst.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dgst.o: ../include/openssl/err.h ../include/openssl/evp.h
dgst.o: ../include/openssl/fips.h ../include/openssl/hmac.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dgst.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dgst.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dgst.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dgst.o: ../include/openssl/sha.h ../include/openssl/stack.h
dgst.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dgst.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h dgst.c
dh.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dh.o: ../include/openssl/dh.h ../include/openssl/e_os2.h
dh.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dh.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dh.o: ../include/openssl/err.h ../include/openssl/evp.h
dh.o: ../include/openssl/fips.h ../include/openssl/lhash.h
dh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dh.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dh.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dh.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dh.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dh.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dh.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dh.o: ../include/openssl/x509_vfy.h apps.h dh.c
dsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dsa.o: ../include/openssl/err.h ../include/openssl/evp.h
dsa.o: ../include/openssl/fips.h ../include/openssl/lhash.h
dsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dsa.o: ../include/openssl/x509_vfy.h apps.h dsa.c
dsaparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dsaparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsaparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dsaparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dsaparam.o: ../include/openssl/evp.h ../include/openssl/fips.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dsaparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsaparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsaparam.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dsaparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.o: ../include/openssl/store.h ../include/openssl/symhacks.h
dsaparam.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
dsaparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
dsaparam.o: dsaparam.c
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ec.o: ../include/openssl/err.h ../include/openssl/evp.h
ec.o: ../include/openssl/fips.h ../include/openssl/lhash.h
ec.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ec.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ec.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ec.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ec.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ec.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ec.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ec.o: ../include/openssl/x509_vfy.h apps.h ec.c
ecparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/engine.h ../include/openssl/err.h
ecparam.o: ../include/openssl/evp.h ../include/openssl/fips.h
ecparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecparam.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ecparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ecparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ecparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ecparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
ecparam.o: ecparam.c
enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
enc.o: ../include/openssl/buffer.h ../include/openssl/conf.h
enc.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
enc.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
enc.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
enc.o: ../include/openssl/err.h ../include/openssl/evp.h
enc.o: ../include/openssl/fips.h ../include/openssl/lhash.h
enc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
enc.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enc.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.o: ../include/openssl/rand.h ../include/openssl/safestack.h
enc.o: ../include/openssl/sha.h ../include/openssl/stack.h
enc.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h enc.c
engine.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/bn.h ../include/openssl/buffer.h
engine.o: ../include/openssl/comp.h ../include/openssl/conf.h
engine.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
engine.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
engine.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
engine.o: ../include/openssl/engine.h ../include/openssl/err.h
engine.o: ../include/openssl/evp.h ../include/openssl/fips.h
engine.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
engine.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
engine.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
engine.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
engine.o: ../include/openssl/safestack.h ../include/openssl/sha.h
engine.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
engine.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
engine.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
engine.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
engine.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
engine.o: engine.c
errstr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
errstr.o: ../include/openssl/comp.h ../include/openssl/conf.h
errstr.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
errstr.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
errstr.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
errstr.o: ../include/openssl/engine.h ../include/openssl/err.h
errstr.o: ../include/openssl/evp.h ../include/openssl/fips.h
errstr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
errstr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
errstr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
errstr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
errstr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
errstr.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
errstr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
errstr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
errstr.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
errstr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
errstr.o: errstr.c
gendh.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendh.o: ../include/openssl/dh.h ../include/openssl/dsa.h
gendh.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
gendh.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
gendh.o: ../include/openssl/engine.h ../include/openssl/err.h
gendh.o: ../include/openssl/evp.h ../include/openssl/fips.h
gendh.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
gendh.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
gendh.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendh.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
gendh.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendh.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendh.o: ../include/openssl/store.h ../include/openssl/symhacks.h
gendh.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
gendh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h gendh.c
gendsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
gendsa.o: ../include/openssl/err.h ../include/openssl/evp.h
gendsa.o: ../include/openssl/fips.h ../include/openssl/lhash.h
gendsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
gendsa.o: ../include/openssl/x509_vfy.h apps.h gendsa.c
genrsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genrsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genrsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genrsa.o: ../include/openssl/dh.h ../include/openssl/dsa.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
genrsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
genrsa.o: ../include/openssl/engine.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/fips.h
genrsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
genrsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/store.h ../include/openssl/symhacks.h
genrsa.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
genrsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
genrsa.o: genrsa.c
nseq.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/buffer.h ../include/openssl/conf.h
nseq.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
nseq.o: ../include/openssl/err.h ../include/openssl/evp.h
nseq.o: ../include/openssl/fips.h ../include/openssl/lhash.h
nseq.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
nseq.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
nseq.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
nseq.o: ../include/openssl/safestack.h ../include/openssl/sha.h
nseq.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
nseq.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
nseq.o: ../include/openssl/x509_vfy.h apps.h nseq.c
ocsp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ocsp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.o: ../include/openssl/comp.h ../include/openssl/conf.h
ocsp.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ocsp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ocsp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ocsp.o: ../include/openssl/engine.h ../include/openssl/err.h
ocsp.o: ../include/openssl/evp.h ../include/openssl/fips.h
ocsp.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ocsp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ocsp.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ocsp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ocsp.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ocsp.o: ../include/openssl/pkcs7.h ../include/openssl/pq_compat.h
ocsp.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ocsp.o: ../include/openssl/sha.h ../include/openssl/ssl.h
ocsp.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ocsp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ocsp.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ocsp.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ocsp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ocsp.c
openssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
openssl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
openssl.o: ../include/openssl/comp.h ../include/openssl/conf.h
openssl.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
openssl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
openssl.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
openssl.o: ../include/openssl/engine.h ../include/openssl/err.h
openssl.o: ../include/openssl/evp.h ../include/openssl/fips.h
openssl.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
openssl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
openssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
openssl.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
openssl.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
openssl.o: openssl.c progs.h s_apps.h
passwd.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
passwd.o: ../include/openssl/buffer.h ../include/openssl/conf.h
passwd.o: ../include/openssl/crypto.h ../include/openssl/des.h
passwd.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
passwd.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
passwd.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
passwd.o: ../include/openssl/err.h ../include/openssl/evp.h
passwd.o: ../include/openssl/fips.h ../include/openssl/lhash.h
passwd.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
passwd.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
passwd.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
passwd.o: ../include/openssl/safestack.h ../include/openssl/sha.h
passwd.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
passwd.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
passwd.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
passwd.o: ../include/openssl/x509_vfy.h apps.h passwd.c
pkcs12.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs12.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs12.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs12.o: ../include/openssl/fips.h ../include/openssl/lhash.h
pkcs12.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs12.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs12.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs12.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs12.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs12.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs12.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs12.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
pkcs12.o: pkcs12.c
pkcs7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs7.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs7.o: ../include/openssl/fips.h ../include/openssl/lhash.h
pkcs7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkcs7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs7.o: ../include/openssl/x509_vfy.h apps.h pkcs7.c
pkcs8.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs8.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs8.o: ../include/openssl/fips.h ../include/openssl/lhash.h
pkcs8.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs8.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs8.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs8.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs8.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs8.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs8.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs8.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h pkcs8.c
prime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/engine.h ../include/openssl/evp.h
prime.o: ../include/openssl/fips.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
prime.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
prime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
prime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
prime.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
prime.o: ../include/openssl/x509_vfy.h apps.h prime.c
rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rand.o: ../include/openssl/err.h ../include/openssl/evp.h
rand.o: ../include/openssl/fips.h ../include/openssl/lhash.h
rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h rand.c
req.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/bn.h ../include/openssl/buffer.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/dh.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
req.o: ../include/openssl/engine.h ../include/openssl/err.h
req.o: ../include/openssl/evp.h ../include/openssl/fips.h
req.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
req.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
req.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
req.o: ../include/openssl/pem.h ../include/openssl/pem2.h
req.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
req.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.o: ../include/openssl/sha.h ../include/openssl/stack.h
req.o: ../include/openssl/store.h ../include/openssl/symhacks.h
req.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
req.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
req.o: ../include/openssl/x509v3.h apps.h req.c
rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.o: ../include/openssl/engine.h ../include/openssl/err.h
rsa.o: ../include/openssl/evp.h ../include/openssl/fips.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsa.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rsa.o: ../include/openssl/x509_vfy.h apps.h rsa.c
rsautl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rsautl.o: ../include/openssl/err.h ../include/openssl/evp.h
rsautl.o: ../include/openssl/fips.h ../include/openssl/lhash.h
rsautl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsautl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsautl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsautl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsautl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
rsautl.o: rsautl.c
s_cb.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_cb.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_cb.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_cb.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_cb.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_cb.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_cb.o: ../include/openssl/engine.h ../include/openssl/err.h
s_cb.o: ../include/openssl/evp.h ../include/openssl/fips.h
s_cb.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_cb.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_cb.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_cb.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
s_cb.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_cb.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_cb.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_cb.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_cb.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h s_apps.h
s_cb.o: s_cb.c
s_client.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_client.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_client.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_client.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.o: ../include/openssl/engine.h ../include/openssl/err.h
s_client.o: ../include/openssl/evp.h ../include/openssl/fips.h
s_client.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_client.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_client.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_client.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_client.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
s_client.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_client.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_client.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_client.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_client.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_client.c timeouts.h
s_server.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_server.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_server.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_server.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_server.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_server.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_server.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_server.o: ../include/openssl/engine.h ../include/openssl/err.h
s_server.o: ../include/openssl/evp.h ../include/openssl/fips.h
s_server.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_server.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_server.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_server.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_server.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
s_server.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_server.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_server.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_server.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_server.o: ../include/openssl/stack.h ../include/openssl/store.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
s_server.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
s_server.o: s_apps.h s_server.c timeouts.h
s_socket.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_socket.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_socket.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_socket.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_socket.o: ../include/openssl/engine.h ../include/openssl/evp.h
s_socket.o: ../include/openssl/fips.h ../include/openssl/kssl.h
s_socket.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_socket.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.o: ../include/openssl/pkcs7.h ../include/openssl/pq_compat.h
s_socket.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s_socket.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_socket.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_socket.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_socket.o: ../include/openssl/x509_vfy.h apps.h s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_time.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_time.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_time.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_time.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_time.o: ../include/openssl/engine.h ../include/openssl/err.h
s_time.o: ../include/openssl/evp.h ../include/openssl/fips.h
s_time.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_time.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_time.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_time.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_time.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_time.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
s_time.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_time.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_time.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_time.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
s_time.o: s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/bn.h ../include/openssl/buffer.h
sess_id.o: ../include/openssl/comp.h ../include/openssl/conf.h
sess_id.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
sess_id.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
sess_id.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
sess_id.o: ../include/openssl/engine.h ../include/openssl/err.h
sess_id.o: ../include/openssl/evp.h ../include/openssl/fips.h
sess_id.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
sess_id.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sess_id.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sess_id.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
sess_id.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
sess_id.o: ../include/openssl/pq_compat.h ../include/openssl/pqueue.h
sess_id.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
sess_id.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
sess_id.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
sess_id.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
sess_id.o: sess_id.c
smime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
smime.o: ../include/openssl/err.h ../include/openssl/evp.h
smime.o: ../include/openssl/fips.h ../include/openssl/lhash.h
smime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
smime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
smime.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
smime.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
smime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
smime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
smime.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
smime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
smime.o: smime.c
speed.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
speed.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
speed.o: ../include/openssl/bn.h ../include/openssl/buffer.h
speed.o: ../include/openssl/cast.h ../include/openssl/conf.h
speed.o: ../include/openssl/crypto.h ../include/openssl/des.h
speed.o: ../include/openssl/des_old.h ../include/openssl/dsa.h
speed.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
speed.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
speed.o: ../include/openssl/engine.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/fips.h
speed.o: ../include/openssl/hmac.h ../include/openssl/idea.h
speed.o: ../include/openssl/lhash.h ../include/openssl/md2.h
speed.o: ../include/openssl/md4.h ../include/openssl/md5.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
speed.o: ../include/openssl/rand.h ../include/openssl/rc2.h
speed.o: ../include/openssl/rc4.h ../include/openssl/ripemd.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/sha.h ../include/openssl/stack.h
speed.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
speed.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h
speed.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h speed.c
speed.o: testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
spkac.o: ../include/openssl/err.h ../include/openssl/evp.h
spkac.o: ../include/openssl/fips.h ../include/openssl/lhash.h
spkac.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
spkac.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
spkac.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
spkac.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
spkac.o: ../include/openssl/safestack.h ../include/openssl/sha.h
spkac.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
spkac.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
spkac.o: ../include/openssl/x509_vfy.h apps.h spkac.c
verify.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
verify.o: ../include/openssl/err.h ../include/openssl/evp.h
verify.o: ../include/openssl/fips.h ../include/openssl/lhash.h
verify.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
verify.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
verify.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
verify.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify.o: ../include/openssl/safestack.h ../include/openssl/sha.h
verify.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
verify.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
verify.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
verify.o: verify.c
version.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
version.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
version.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
version.o: ../include/openssl/evp.h ../include/openssl/fips.h
version.o: ../include/openssl/idea.h ../include/openssl/lhash.h
version.o: ../include/openssl/md2.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
version.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
version.o: ../include/openssl/pkcs7.h ../include/openssl/rc4.h
version.o: ../include/openssl/safestack.h ../include/openssl/sha.h
version.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
version.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
version.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
version.o: ../include/openssl/x509_vfy.h apps.h version.c
x509.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
x509.o: ../include/openssl/err.h ../include/openssl/evp.h
x509.o: ../include/openssl/fips.h ../include/openssl/lhash.h
x509.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
x509.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
x509.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
x509.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
x509.o: ../include/openssl/x509v3.h apps.h x509.c
