#
#  apps/Makefile
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../crypto -I../include
CFLAG=		-g -static -Wswitch
MAKEFILE=	Makefile
PERL=		perl
RM=		rm -f

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

SHLIB_TARGET=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile makeapps.com install.com

DLIBCRYPTO=../libcrypto.a
DLIBSSL=../libssl.a
LIBCRYPTO=-L.. -lcrypto
LIBSSL=-L.. -lssl

SCRIPTS=CA.pl tsget
EXE= openssl$(EXE_EXT)

COMMANDS= \
	asn1pars.o ca.o ciphers.o cms.o crl.o crl2p7.o dgst.o dhparam.o \
	dsa.o dsaparam.o ec.o ecparam.o enc.o engine.o errstr.o gendsa.o \
	genpkey.o genrsa.o nseq.o ocsp.o passwd.o pkcs12.o pkcs7.o pkcs8.o \
	pkey.o pkeyparam.o pkeyutl.o prime.o rand.o req.o rsa.o rsautl.o \
	s_client.o s_server.o s_time.o sess_id.o smime.o speed.o spkac.o \
	srp.o ts.o verify.o version.o x509.o rehash.o

EXTRA_OBJ=apps.o opt.o s_cb.o s_socket.o
EXTRA_SRC=apps.c opt.c s_cb.c s_socket.c
RAND_OBJ=app_rand.o
RAND_SRC=app_rand.c

OBJ	= $(COMMANDS)

SRC	= \
	asn1pars.c ca.c ciphers.c cms.c crl.c crl2p7.c dgst.c dhparam.c \
	dsa.c dsaparam.c ec.c ecparam.c enc.c engine.c errstr.c gendsa.c \
	genpkey.c genrsa.c nseq.c ocsp.c passwd.c pkcs12.c pkcs7.c pkcs8.c \
	pkey.c pkeyparam.c pkeyutl.c prime.c rand.c req.c rsa.c rsautl.c \
	s_client.c s_server.c s_time.c sess_id.c smime.c speed.c spkac.c \
	srp.c ts.c verify.c version.c x509.c

EXE_OBJ	= openssl.o $(OBJ) $(EXTRA_OBJ) $(RAND_OBJ)
EXE_SRC = openssl.c $(SRC) $(EXTRA_SRC) $(RAND_SRC)

HEADER=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h timeouts.h

ALL=    $(GENERAL) $(EXE_SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	exe

exe:	$(EXE)

openssl-vms.cnf: openssl.cnf
	$(PERL) $(TOP)/VMS/VMSify-conf.pl < openssl.cnf > openssl-vms.cnf

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

uninstall:
	@set -e; for i in $(EXE); \
	do  \
		echo $(RM) $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
		$(RM) $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
	done;
	@set -e; for i in $(SCRIPTS); \
	do  \
		echo $(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
		$(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
	done
	$(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

tags:
	ctags $(EXE_SRC) $(HEADER)

tests:

lint:
	echo nope >fluff

update: openssl-vms.cnf local_depend

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(EXE_SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) build_libssl)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) build_libcrypto)

$(EXE): progs.h $(EXE_OBJ) $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(EXE)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO)" ; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$(EXE) OBJECTS="$(EXE_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl Makefile
	$(RM) progs.h
	$(PERL) progs.pl $(COMMANDS) >progs.h
	$(RM) openssl.o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
app_rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
app_rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
app_rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
app_rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
app_rand.o: ../include/openssl/evp.h ../include/openssl/lhash.h
app_rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
app_rand.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
app_rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
app_rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
app_rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
app_rand.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
app_rand.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
app_rand.o: app_rand.c apps.h progs.h
apps.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/comp.h ../include/openssl/conf.h
apps.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.o: ../include/openssl/engine.h ../include/openssl/err.h
apps.o: ../include/openssl/evp.h ../include/openssl/hmac.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
apps.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
apps.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
apps.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
apps.o: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
apps.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
apps.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
apps.o: ../include/openssl/ui.h ../include/openssl/x509.h
apps.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.c apps.h
apps.o: progs.h
asn1pars.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
asn1pars.o: ../include/openssl/err.h ../include/openssl/evp.h
asn1pars.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
asn1pars.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
asn1pars.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
asn1pars.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
asn1pars.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
asn1pars.o: ../include/openssl/safestack.h ../include/openssl/sha.h
asn1pars.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
asn1pars.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
asn1pars.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
asn1pars.o: asn1pars.c progs.h
ca.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.o: ../include/openssl/engine.h ../include/openssl/err.h
ca.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ca.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ca.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ca.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ca.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ca.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ca.o: ../include/openssl/sha.h ../include/openssl/stack.h
ca.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ca.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ca.o: ../include/openssl/x509v3.h apps.h ca.c progs.h
ciphers.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ciphers.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ciphers.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ciphers.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ciphers.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ciphers.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ciphers.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ciphers.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ciphers.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ciphers.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ciphers.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ciphers.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ciphers.o: ciphers.c progs.h
cms.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
cms.o: ../include/openssl/buffer.h ../include/openssl/cms.h
cms.o: ../include/openssl/conf.h ../include/openssl/crypto.h
cms.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
cms.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
cms.o: ../include/openssl/engine.h ../include/openssl/err.h
cms.o: ../include/openssl/evp.h ../include/openssl/lhash.h
cms.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
cms.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
cms.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
cms.o: ../include/openssl/pem.h ../include/openssl/pem2.h
cms.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
cms.o: ../include/openssl/sha.h ../include/openssl/stack.h
cms.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
cms.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
cms.o: ../include/openssl/x509v3.h apps.h cms.c progs.h
crl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl.o: ../include/openssl/err.h ../include/openssl/evp.h
crl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
crl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
crl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h crl.c
crl.o: progs.h
crl2p7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl2p7.o: ../include/openssl/err.h ../include/openssl/evp.h
crl2p7.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
crl2p7.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
crl2p7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl2p7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl2p7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl2p7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl2p7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl2p7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl2p7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
crl2p7.o: crl2p7.c progs.h
dgst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dgst.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dgst.o: ../include/openssl/err.h ../include/openssl/evp.h
dgst.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
dgst.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dgst.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dgst.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dgst.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dgst.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dgst.o: ../include/openssl/sha.h ../include/openssl/stack.h
dgst.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dgst.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dgst.o: ../include/openssl/x509v3.h apps.h dgst.c progs.h
dhparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dhparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dhparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dhparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dhparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dhparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dhparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dhparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dhparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dhparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dhparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dhparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dhparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dhparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dhparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dhparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dhparam.o: ../include/openssl/x509v3.h apps.h dhparam.c progs.h
dsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dsa.o: ../include/openssl/err.h ../include/openssl/evp.h
dsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h dsa.c
dsa.o: progs.h
dsaparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsaparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsaparam.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dsaparam.o: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsaparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsaparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsaparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsaparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsaparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dsaparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
dsaparam.o: dsaparam.c progs.h
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ec.o: ../include/openssl/err.h ../include/openssl/evp.h
ec.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ec.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ec.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ec.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ec.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ec.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ec.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ec.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ec.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ec.c
ec.o: progs.h
ecparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/engine.h ../include/openssl/err.h
ecparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ecparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ecparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ecparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ecparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ecparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ecparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ecparam.o: ../include/openssl/x509v3.h apps.h ecparam.c progs.h
enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
enc.o: ../include/openssl/buffer.h ../include/openssl/comp.h
enc.o: ../include/openssl/conf.h ../include/openssl/crypto.h
enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enc.o: ../include/openssl/engine.h ../include/openssl/err.h
enc.o: ../include/openssl/evp.h ../include/openssl/lhash.h
enc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
enc.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
enc.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
enc.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
enc.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h enc.c
enc.o: progs.h
engine.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/buffer.h ../include/openssl/comp.h
engine.o: ../include/openssl/conf.h ../include/openssl/crypto.h
engine.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
engine.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
engine.o: ../include/openssl/err.h ../include/openssl/evp.h
engine.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
engine.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.o: ../include/openssl/pem.h ../include/openssl/pem2.h
engine.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
engine.o: ../include/openssl/sha.h ../include/openssl/srtp.h
engine.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
engine.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
engine.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
engine.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
engine.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
engine.o: engine.c progs.h
errstr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/buffer.h ../include/openssl/comp.h
errstr.o: ../include/openssl/conf.h ../include/openssl/crypto.h
errstr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
errstr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
errstr.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
errstr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
errstr.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
errstr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
errstr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
errstr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
errstr.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
errstr.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
errstr.o: errstr.c progs.h
gendsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
gendsa.o: ../include/openssl/err.h ../include/openssl/evp.h
gendsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
gendsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
gendsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
gendsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
gendsa.o: gendsa.c progs.h
genpkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genpkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
genpkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
genpkey.o: ../include/openssl/err.h ../include/openssl/evp.h
genpkey.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
genpkey.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
genpkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
genpkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
genpkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genpkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
genpkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
genpkey.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
genpkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
genpkey.o: genpkey.c progs.h
genrsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genrsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genrsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
genrsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
genrsa.o: ../include/openssl/engine.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genrsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genrsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genrsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genrsa.o: ../include/openssl/x509v3.h apps.h genrsa.c progs.h
nseq.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/buffer.h ../include/openssl/conf.h
nseq.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
nseq.o: ../include/openssl/err.h ../include/openssl/evp.h
nseq.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
nseq.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
nseq.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
nseq.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
nseq.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
nseq.o: ../include/openssl/safestack.h ../include/openssl/sha.h
nseq.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
nseq.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
nseq.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h nseq.c
nseq.o: progs.h
ocsp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ocsp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.o: ../include/openssl/comp.h ../include/openssl/conf.h
ocsp.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ocsp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ocsp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ocsp.o: ../include/openssl/engine.h ../include/openssl/err.h
ocsp.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ocsp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ocsp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ocsp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ocsp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ocsp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ocsp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ocsp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ocsp.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ocsp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ocsp.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ocsp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ocsp.o: ../include/openssl/x509v3.h apps.h ocsp.c progs.h
openssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
openssl.o: ../include/openssl/buffer.h ../include/openssl/comp.h
openssl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
openssl.o: ../include/openssl/err.h ../include/openssl/evp.h
openssl.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
openssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
openssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
openssl.o: ../include/openssl/x509v3.h apps.h openssl.c progs.h s_apps.h
opt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
opt.o: ../include/openssl/buffer.h ../include/openssl/conf.h
opt.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
opt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
opt.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
opt.o: ../include/openssl/evp.h ../include/openssl/lhash.h
opt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
opt.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
opt.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
opt.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
opt.o: ../include/openssl/sha.h ../include/openssl/stack.h
opt.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
opt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
opt.o: ../include/openssl/x509v3.h apps.h opt.c progs.h
passwd.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
passwd.o: ../include/openssl/buffer.h ../include/openssl/conf.h
passwd.o: ../include/openssl/crypto.h ../include/openssl/des.h
passwd.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
passwd.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
passwd.o: ../include/openssl/engine.h ../include/openssl/err.h
passwd.o: ../include/openssl/evp.h ../include/openssl/lhash.h
passwd.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
passwd.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
passwd.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
passwd.o: ../include/openssl/rand.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
passwd.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
passwd.o: ../include/openssl/x509v3.h apps.h passwd.c progs.h
pkcs12.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs12.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs12.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs12.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs12.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs12.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs12.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs12.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs12.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs12.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs12.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs12.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs12.o: ../include/openssl/x509v3.h apps.h pkcs12.c progs.h
pkcs7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs7.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs7.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs7.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkcs7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs7.o: pkcs7.c progs.h
pkcs8.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs8.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs8.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs8.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs8.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs8.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs8.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs8.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs8.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs8.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs8.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs8.o: ../include/openssl/x509v3.h apps.h pkcs8.c progs.h
pkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkey.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkey.o: ../include/openssl/err.h ../include/openssl/evp.h
pkey.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkey.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkey.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h pkey.c
pkey.o: progs.h
pkeyparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyparam.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkeyparam.o: ../include/openssl/err.h ../include/openssl/evp.h
pkeyparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkeyparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkeyparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkeyparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyparam.o: pkeyparam.c progs.h
pkeyutl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyutl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyutl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkeyutl.o: ../include/openssl/err.h ../include/openssl/evp.h
pkeyutl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkeyutl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkeyutl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyutl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyutl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyutl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyutl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyutl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkeyutl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyutl.o: pkeyutl.c progs.h
prime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/engine.h ../include/openssl/evp.h
prime.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
prime.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
prime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
prime.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
prime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
prime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
prime.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
prime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
prime.o: prime.c progs.h
rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rand.o: ../include/openssl/err.h ../include/openssl/evp.h
rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rand.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rand.o: ../include/openssl/x509v3.h apps.h progs.h rand.c
req.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/bn.h ../include/openssl/buffer.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
req.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
req.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
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
req.o: ../include/openssl/x509v3.h apps.h progs.h req.c
rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.o: ../include/openssl/engine.h ../include/openssl/err.h
rsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsa.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
rsa.o: rsa.c
rsautl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rsautl.o: ../include/openssl/err.h ../include/openssl/evp.h
rsautl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsautl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsautl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsautl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsautl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsautl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsautl.o: ../include/openssl/x509v3.h apps.h progs.h rsautl.c
s_cb.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_cb.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_cb.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_cb.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_cb.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_cb.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_cb.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_cb.o: ../include/openssl/err.h ../include/openssl/evp.h
s_cb.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_cb.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_cb.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_cb.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_cb.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_cb.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_cb.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_cb.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_cb.o: ../include/openssl/x509v3.h apps.h progs.h s_apps.h s_cb.c
s_client.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_client.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_client.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_client.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.o: ../include/openssl/engine.h ../include/openssl/err.h
s_client.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_client.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_client.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_client.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_client.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_client.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_client.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_client.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_client.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_client.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_client.o: ../include/openssl/x509v3.h apps.h progs.h s_apps.h s_client.c
s_client.o: timeouts.h
s_server.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/async.h
s_server.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_server.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_server.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_server.o: ../include/openssl/dh.h ../include/openssl/dtls1.h
s_server.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_server.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_server.o: ../include/openssl/engine.h ../include/openssl/err.h
s_server.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_server.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_server.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_server.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_server.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_server.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_server.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_server.o: ../include/openssl/srp.h ../include/openssl/srtp.h
s_server.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_server.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_server.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_server.o: progs.h s_apps.h s_server.c timeouts.h
s_socket.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_socket.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_socket.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_socket.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_socket.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_socket.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_socket.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_socket.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_socket.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_socket.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_socket.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_socket.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_socket.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_socket.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_socket.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_socket.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_socket.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_socket.o: ../include/openssl/x509v3.h apps.h progs.h s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_time.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_time.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_time.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_time.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_time.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_time.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_time.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
s_time.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_time.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_time.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_time.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_time.o: progs.h s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/buffer.h ../include/openssl/comp.h
sess_id.o: ../include/openssl/conf.h ../include/openssl/crypto.h
sess_id.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
sess_id.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
sess_id.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
sess_id.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sess_id.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
sess_id.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
sess_id.o: ../include/openssl/sha.h ../include/openssl/srtp.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sess_id.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sess_id.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
sess_id.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
sess_id.o: progs.h sess_id.c
smime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
smime.o: ../include/openssl/err.h ../include/openssl/evp.h
smime.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
smime.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
smime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
smime.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
smime.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
smime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
smime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
smime.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
smime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
smime.o: progs.h smime.c
speed.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
speed.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
speed.o: ../include/openssl/bn.h ../include/openssl/buffer.h
speed.o: ../include/openssl/camellia.h ../include/openssl/cast.h
speed.o: ../include/openssl/conf.h ../include/openssl/crypto.h
speed.o: ../include/openssl/des.h ../include/openssl/dsa.h
speed.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
speed.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
speed.o: ../include/openssl/engine.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.o: ../include/openssl/idea.h ../include/openssl/lhash.h
speed.o: ../include/openssl/md4.h ../include/openssl/md5.h
speed.o: ../include/openssl/mdc2.h ../include/openssl/modes.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
speed.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
speed.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
speed.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
speed.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
speed.o: ../include/openssl/safestack.h ../include/openssl/seed.h
speed.o: ../include/openssl/sha.h ../include/openssl/stack.h
speed.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
speed.o: ../include/openssl/whrlpool.h ../include/openssl/x509.h
speed.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
speed.o: progs.h speed.c testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
spkac.o: ../include/openssl/err.h ../include/openssl/evp.h
spkac.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
spkac.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
spkac.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
spkac.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
spkac.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
spkac.o: ../include/openssl/safestack.h ../include/openssl/sha.h
spkac.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
spkac.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
spkac.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
spkac.o: progs.h spkac.c
srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
srp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
srp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
srp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
srp.o: ../include/openssl/engine.h ../include/openssl/err.h
srp.o: ../include/openssl/evp.h ../include/openssl/lhash.h
srp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
srp.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
srp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
srp.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
srp.o: ../include/openssl/sha.h ../include/openssl/srp.h
srp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
srp.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
srp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
srp.o: srp.c
ts.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ts.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ts.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ts.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ts.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ts.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ts.o: ../include/openssl/engine.h ../include/openssl/err.h
ts.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ts.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ts.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ts.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ts.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ts.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ts.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ts.o: ../include/openssl/sha.h ../include/openssl/stack.h
ts.o: ../include/openssl/symhacks.h ../include/openssl/ts.h
ts.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ts.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
ts.o: ts.c
verify.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
verify.o: ../include/openssl/err.h ../include/openssl/evp.h
verify.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
verify.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
verify.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
verify.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
verify.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify.o: ../include/openssl/safestack.h ../include/openssl/sha.h
verify.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
verify.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
verify.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
verify.o: progs.h verify.c
version.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
version.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
version.o: ../include/openssl/engine.h ../include/openssl/evp.h
version.o: ../include/openssl/idea.h ../include/openssl/lhash.h
version.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
version.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
version.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
version.o: ../include/openssl/pkcs7.h ../include/openssl/rc4.h
version.o: ../include/openssl/safestack.h ../include/openssl/sha.h
version.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
version.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
version.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
version.o: progs.h version.c
x509.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
x509.o: ../include/openssl/err.h ../include/openssl/evp.h
x509.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
x509.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
x509.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
x509.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
x509.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
x509.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
x509.o: ../include/openssl/x509v3.h apps.h progs.h x509.c
