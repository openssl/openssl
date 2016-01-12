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

progs.h: progs.pl Makefile
	$(RM) progs.h
	$(PERL) progs.pl $(COMMANDS) >progs.h
	$(RM) openssl.o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
app_rand.o: ../include/openssl/bn.h ../include/openssl/buffer.h
app_rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
app_rand.o: ../include/openssl/dh.h ../include/openssl/dsa.h
app_rand.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
app_rand.o: ../include/openssl/engine.h ../include/openssl/err.h
app_rand.o: ../include/openssl/evp.h ../include/openssl/lhash.h
app_rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
app_rand.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
app_rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
app_rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
app_rand.o: ../include/openssl/ui.h ../include/openssl/x509.h
app_rand.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
app_rand.o: app_rand.c apps.h progs.h
apps.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/comp.h ../include/openssl/conf.h
apps.o: ../include/openssl/crypto.h ../include/openssl/dh.h
apps.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/engine.h ../include/openssl/err.h
apps.o: ../include/openssl/evp.h ../include/openssl/hmac.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
apps.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
apps.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
apps.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
apps.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
apps.o: ../include/openssl/sha.h ../include/openssl/srtp.h
apps.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
apps.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
apps.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
apps.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
apps.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
apps.o: ../include/openssl/x509v3.h apps.c apps.h progs.h
asn1pars.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/bn.h ../include/openssl/buffer.h
asn1pars.o: ../include/openssl/conf.h ../include/openssl/crypto.h
asn1pars.o: ../include/openssl/dh.h ../include/openssl/dsa.h
asn1pars.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
asn1pars.o: ../include/openssl/engine.h ../include/openssl/err.h
asn1pars.o: ../include/openssl/evp.h ../include/openssl/lhash.h
asn1pars.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
asn1pars.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
asn1pars.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
asn1pars.o: ../include/openssl/pem.h ../include/openssl/pem2.h
asn1pars.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
asn1pars.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
asn1pars.o: ../include/openssl/sha.h ../include/openssl/stack.h
asn1pars.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
asn1pars.o: ../include/openssl/ui.h ../include/openssl/x509.h
asn1pars.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
asn1pars.o: asn1pars.c progs.h
ca.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/engine.h ../include/openssl/err.h
ca.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ca.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ca.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ca.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ca.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ca.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ca.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ca.o: ../include/openssl/sha.h ../include/openssl/stack.h
ca.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ca.o: ../include/openssl/ui.h ../include/openssl/x509.h
ca.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ca.c
ca.o: progs.h
ciphers.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ciphers.o: ../include/openssl/comp.h ../include/openssl/conf.h
ciphers.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ciphers.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ciphers.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ciphers.o: ../include/openssl/engine.h ../include/openssl/err.h
ciphers.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ciphers.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ciphers.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ciphers.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ciphers.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ciphers.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ciphers.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ciphers.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ciphers.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ciphers.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ciphers.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ciphers.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ciphers.o: ../include/openssl/ui.h ../include/openssl/x509.h
ciphers.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ciphers.o: ciphers.c progs.h
cms.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
cms.o: ../include/openssl/bn.h ../include/openssl/buffer.h
cms.o: ../include/openssl/cms.h ../include/openssl/conf.h
cms.o: ../include/openssl/crypto.h ../include/openssl/dh.h
cms.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
cms.o: ../include/openssl/ec.h ../include/openssl/engine.h
cms.o: ../include/openssl/err.h ../include/openssl/evp.h
cms.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
cms.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
cms.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cms.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
cms.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
cms.o: ../include/openssl/rand.h ../include/openssl/rsa.h
cms.o: ../include/openssl/safestack.h ../include/openssl/sha.h
cms.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
cms.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
cms.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
cms.o: ../include/openssl/x509v3.h apps.h cms.c progs.h
crl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
crl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl.o: ../include/openssl/dh.h ../include/openssl/dsa.h
crl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
crl.o: ../include/openssl/engine.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
crl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
crl.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl.o: ../include/openssl/ui.h ../include/openssl/x509.h
crl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h crl.c
crl.o: progs.h
crl2p7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/bn.h ../include/openssl/buffer.h
crl2p7.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl2p7.o: ../include/openssl/dh.h ../include/openssl/dsa.h
crl2p7.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
crl2p7.o: ../include/openssl/engine.h ../include/openssl/err.h
crl2p7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl2p7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl2p7.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl2p7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl2p7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl2p7.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
crl2p7.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
crl2p7.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl2p7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl2p7.o: ../include/openssl/ui.h ../include/openssl/x509.h
crl2p7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
crl2p7.o: crl2p7.c progs.h
dgst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dgst.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dgst.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dgst.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dgst.o: ../include/openssl/engine.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/hmac.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dgst.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dgst.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dgst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dgst.o: ../include/openssl/rand.h ../include/openssl/rsa.h
dgst.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dgst.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dgst.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
dgst.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dgst.o: ../include/openssl/x509v3.h apps.h dgst.c progs.h
dhparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dhparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dhparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dhparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dhparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dhparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dhparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dhparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dhparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dhparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dhparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dhparam.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dhparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dhparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dhparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dhparam.o: ../include/openssl/ui.h ../include/openssl/x509.h
dhparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
dhparam.o: dhparam.c progs.h
dsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsa.o: ../include/openssl/engine.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsa.o: ../include/openssl/ui.h ../include/openssl/x509.h
dsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h dsa.c
dsa.o: progs.h
dsaparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dsaparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsaparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dsaparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dsaparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsaparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dsaparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsaparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsaparam.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
dsaparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsaparam.o: ../include/openssl/ui.h ../include/openssl/x509.h
dsaparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
dsaparam.o: dsaparam.c progs.h
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ec.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ec.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ec.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ec.o: ../include/openssl/engine.h ../include/openssl/err.h
ec.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ec.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ec.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ec.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ec.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ec.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ec.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ec.o: ../include/openssl/sha.h ../include/openssl/stack.h
ec.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ec.o: ../include/openssl/ui.h ../include/openssl/x509.h
ec.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ec.c
ec.o: progs.h
ecparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/engine.h ../include/openssl/err.h
ecparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ecparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ecparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ecparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ecparam.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ecparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ecparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ecparam.o: ../include/openssl/ui.h ../include/openssl/x509.h
ecparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ecparam.o: ecparam.c progs.h
enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
enc.o: ../include/openssl/bn.h ../include/openssl/buffer.h
enc.o: ../include/openssl/comp.h ../include/openssl/conf.h
enc.o: ../include/openssl/crypto.h ../include/openssl/dh.h
enc.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
enc.o: ../include/openssl/ec.h ../include/openssl/engine.h
enc.o: ../include/openssl/err.h ../include/openssl/evp.h
enc.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
enc.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enc.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.o: ../include/openssl/rand.h ../include/openssl/rsa.h
enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
enc.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
enc.o: ../include/openssl/x509v3.h apps.h enc.c progs.h
engine.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/bn.h ../include/openssl/buffer.h
engine.o: ../include/openssl/comp.h ../include/openssl/conf.h
engine.o: ../include/openssl/crypto.h ../include/openssl/dh.h
engine.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
engine.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
engine.o: ../include/openssl/engine.h ../include/openssl/err.h
engine.o: ../include/openssl/evp.h ../include/openssl/hmac.h
engine.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
engine.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
engine.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
engine.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
engine.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
engine.o: ../include/openssl/rand.h ../include/openssl/rsa.h
engine.o: ../include/openssl/safestack.h ../include/openssl/sha.h
engine.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
engine.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
engine.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
engine.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
engine.o: ../include/openssl/ui.h ../include/openssl/x509.h
engine.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
engine.o: engine.c progs.h
errstr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
errstr.o: ../include/openssl/comp.h ../include/openssl/conf.h
errstr.o: ../include/openssl/crypto.h ../include/openssl/dh.h
errstr.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
errstr.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
errstr.o: ../include/openssl/engine.h ../include/openssl/err.h
errstr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
errstr.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
errstr.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
errstr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
errstr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
errstr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
errstr.o: ../include/openssl/rand.h ../include/openssl/rsa.h
errstr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
errstr.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
errstr.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
errstr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
errstr.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
errstr.o: ../include/openssl/ui.h ../include/openssl/x509.h
errstr.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
errstr.o: errstr.c progs.h
gendsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dh.h ../include/openssl/dsa.h
gendsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
gendsa.o: ../include/openssl/engine.h ../include/openssl/err.h
gendsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
gendsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
gendsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
gendsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendsa.o: ../include/openssl/ui.h ../include/openssl/x509.h
gendsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
gendsa.o: gendsa.c progs.h
genpkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genpkey.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genpkey.o: ../include/openssl/dh.h ../include/openssl/dsa.h
genpkey.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
genpkey.o: ../include/openssl/engine.h ../include/openssl/err.h
genpkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genpkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genpkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genpkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genpkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genpkey.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genpkey.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genpkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
genpkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genpkey.o: ../include/openssl/ui.h ../include/openssl/x509.h
genpkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
genpkey.o: genpkey.c progs.h
genrsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genrsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genrsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genrsa.o: ../include/openssl/dh.h ../include/openssl/dsa.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
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
genrsa.o: ../include/openssl/ui.h ../include/openssl/x509.h
genrsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
genrsa.o: genrsa.c progs.h
nseq.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/bn.h ../include/openssl/buffer.h
nseq.o: ../include/openssl/conf.h ../include/openssl/crypto.h
nseq.o: ../include/openssl/dh.h ../include/openssl/dsa.h
nseq.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
nseq.o: ../include/openssl/engine.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/lhash.h
nseq.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
nseq.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
nseq.o: ../include/openssl/pem.h ../include/openssl/pem2.h
nseq.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
nseq.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
nseq.o: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
nseq.o: ../include/openssl/ui.h ../include/openssl/x509.h
nseq.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h nseq.c
nseq.o: progs.h
ocsp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ocsp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.o: ../include/openssl/comp.h ../include/openssl/conf.h
ocsp.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ocsp.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ocsp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ocsp.o: ../include/openssl/engine.h ../include/openssl/err.h
ocsp.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ocsp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ocsp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ocsp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ocsp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ocsp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ocsp.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ocsp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ocsp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ocsp.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ocsp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ocsp.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ocsp.o: ../include/openssl/ui.h ../include/openssl/x509.h
ocsp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ocsp.c
ocsp.o: progs.h
openssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
openssl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
openssl.o: ../include/openssl/comp.h ../include/openssl/conf.h
openssl.o: ../include/openssl/crypto.h ../include/openssl/dh.h
openssl.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
openssl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
openssl.o: ../include/openssl/engine.h ../include/openssl/err.h
openssl.o: ../include/openssl/evp.h ../include/openssl/hmac.h
openssl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
openssl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
openssl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
openssl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
openssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
openssl.o: ../include/openssl/rand.h ../include/openssl/rsa.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
openssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/ui.h ../include/openssl/x509.h
openssl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
openssl.o: openssl.c progs.h s_apps.h
opt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
opt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
opt.o: ../include/openssl/conf.h ../include/openssl/crypto.h
opt.o: ../include/openssl/dh.h ../include/openssl/dsa.h
opt.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
opt.o: ../include/openssl/engine.h ../include/openssl/err.h
opt.o: ../include/openssl/evp.h ../include/openssl/lhash.h
opt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
opt.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
opt.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
opt.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
opt.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
opt.o: ../include/openssl/sha.h ../include/openssl/stack.h
opt.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
opt.o: ../include/openssl/ui.h ../include/openssl/x509.h
opt.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h opt.c
opt.o: progs.h
passwd.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
passwd.o: ../include/openssl/bn.h ../include/openssl/buffer.h
passwd.o: ../include/openssl/conf.h ../include/openssl/crypto.h
passwd.o: ../include/openssl/des.h ../include/openssl/dh.h
passwd.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
passwd.o: ../include/openssl/ec.h ../include/openssl/engine.h
passwd.o: ../include/openssl/err.h ../include/openssl/evp.h
passwd.o: ../include/openssl/lhash.h ../include/openssl/md5.h
passwd.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
passwd.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
passwd.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
passwd.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
passwd.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
passwd.o: ../include/openssl/ui.h ../include/openssl/x509.h
passwd.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
passwd.o: passwd.c progs.h
pkcs12.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkcs12.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs12.o: ../include/openssl/dh.h ../include/openssl/dsa.h
pkcs12.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkcs12.o: ../include/openssl/engine.h ../include/openssl/err.h
pkcs12.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs12.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs12.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs12.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs12.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs12.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs12.o: ../include/openssl/rand.h ../include/openssl/rsa.h
pkcs12.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs12.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs12.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
pkcs12.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs12.o: ../include/openssl/x509v3.h apps.h pkcs12.c progs.h
pkcs7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkcs7.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs7.o: ../include/openssl/dh.h ../include/openssl/dsa.h
pkcs7.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkcs7.o: ../include/openssl/engine.h ../include/openssl/err.h
pkcs7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs7.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs7.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
pkcs7.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
pkcs7.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs7.o: ../include/openssl/ui.h ../include/openssl/x509.h
pkcs7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs7.o: pkcs7.c progs.h
pkcs8.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkcs8.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs8.o: ../include/openssl/dh.h ../include/openssl/dsa.h
pkcs8.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkcs8.o: ../include/openssl/engine.h ../include/openssl/err.h
pkcs8.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs8.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs8.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs8.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs8.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs8.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs8.o: ../include/openssl/rand.h ../include/openssl/rsa.h
pkcs8.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs8.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs8.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
pkcs8.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs8.o: ../include/openssl/x509v3.h apps.h pkcs8.c progs.h
pkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkey.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkey.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkey.o: ../include/openssl/dh.h ../include/openssl/dsa.h
pkey.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkey.o: ../include/openssl/engine.h ../include/openssl/err.h
pkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkey.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
pkey.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
pkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkey.o: ../include/openssl/ui.h ../include/openssl/x509.h
pkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h pkey.c
pkey.o: progs.h
pkeyparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkeyparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkeyparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
pkeyparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkeyparam.o: ../include/openssl/engine.h ../include/openssl/err.h
pkeyparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyparam.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
pkeyparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
pkeyparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyparam.o: ../include/openssl/ui.h ../include/openssl/x509.h
pkeyparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyparam.o: pkeyparam.c progs.h
pkeyutl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
pkeyutl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkeyutl.o: ../include/openssl/dh.h ../include/openssl/dsa.h
pkeyutl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkeyutl.o: ../include/openssl/engine.h ../include/openssl/err.h
pkeyutl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyutl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyutl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyutl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyutl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyutl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
pkeyutl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
pkeyutl.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyutl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyutl.o: ../include/openssl/ui.h ../include/openssl/x509.h
pkeyutl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyutl.o: pkeyutl.c progs.h
prime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/dh.h ../include/openssl/dsa.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/engine.h ../include/openssl/err.h
prime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
prime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
prime.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
prime.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
prime.o: ../include/openssl/sha.h ../include/openssl/stack.h
prime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
prime.o: ../include/openssl/ui.h ../include/openssl/x509.h
prime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
prime.o: prime.c progs.h
rand.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rand.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.o: ../include/openssl/dh.h ../include/openssl/dsa.h
rand.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rand.o: ../include/openssl/engine.h ../include/openssl/err.h
rand.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rand.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rand.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.o: ../include/openssl/ui.h ../include/openssl/x509.h
rand.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rand.o: progs.h rand.c
req.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/bn.h ../include/openssl/buffer.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/dh.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.o: ../include/openssl/engine.h ../include/openssl/err.h
req.o: ../include/openssl/evp.h ../include/openssl/lhash.h
req.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
req.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
req.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
req.o: ../include/openssl/pem.h ../include/openssl/pem2.h
req.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
req.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.o: ../include/openssl/sha.h ../include/openssl/stack.h
req.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
req.o: ../include/openssl/ui.h ../include/openssl/x509.h
req.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
req.o: req.c
rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/dh.h ../include/openssl/dsa.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/engine.h ../include/openssl/err.h
rsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsa.o: ../include/openssl/ui.h ../include/openssl/x509.h
rsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
rsa.o: rsa.c
rsautl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsautl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsautl.o: ../include/openssl/dh.h ../include/openssl/dsa.h
rsautl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsautl.o: ../include/openssl/engine.h ../include/openssl/err.h
rsautl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsautl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsautl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsautl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsautl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsautl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsautl.o: ../include/openssl/ui.h ../include/openssl/x509.h
rsautl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rsautl.o: progs.h rsautl.c
s_cb.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_cb.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_cb.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_cb.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_cb.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_cb.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_cb.o: ../include/openssl/engine.h ../include/openssl/err.h
s_cb.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_cb.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_cb.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_cb.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_cb.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_cb.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_cb.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_cb.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_cb.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_cb.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_cb.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_cb.o: ../include/openssl/ui.h ../include/openssl/x509.h
s_cb.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_cb.o: progs.h s_apps.h s_cb.c
s_client.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/async.h
s_client.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_client.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_client.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_client.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_client.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_client.o: ../include/openssl/ec.h ../include/openssl/engine.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_client.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_client.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_client.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_client.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_client.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_client.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_client.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_client.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_client.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_client.o: ../include/openssl/ui.h ../include/openssl/x509.h
s_client.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_client.o: progs.h s_apps.h s_client.c timeouts.h
s_server.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/async.h
s_server.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_server.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_server.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_server.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_server.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_server.o: ../include/openssl/ec.h ../include/openssl/engine.h
s_server.o: ../include/openssl/err.h ../include/openssl/evp.h
s_server.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_server.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_server.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_server.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_server.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_server.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_server.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_server.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_server.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_server.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_server.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_server.o: ../include/openssl/ui.h ../include/openssl/x509.h
s_server.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_server.o: progs.h s_apps.h s_server.c timeouts.h
s_socket.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_socket.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_socket.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_socket.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_socket.o: ../include/openssl/engine.h ../include/openssl/err.h
s_socket.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_socket.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_socket.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_socket.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_socket.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_socket.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_socket.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_socket.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_socket.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_socket.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_socket.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_socket.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_socket.o: ../include/openssl/ui.h ../include/openssl/x509.h
s_socket.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_socket.o: progs.h s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s_time.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_time.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_time.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_time.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_time.o: ../include/openssl/engine.h ../include/openssl/err.h
s_time.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_time.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_time.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_time.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_time.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_time.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_time.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_time.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_time.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_time.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_time.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_time.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_time.o: ../include/openssl/ui.h ../include/openssl/x509.h
s_time.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_time.o: progs.h s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/bn.h ../include/openssl/buffer.h
sess_id.o: ../include/openssl/comp.h ../include/openssl/conf.h
sess_id.o: ../include/openssl/crypto.h ../include/openssl/dh.h
sess_id.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
sess_id.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
sess_id.o: ../include/openssl/engine.h ../include/openssl/err.h
sess_id.o: ../include/openssl/evp.h ../include/openssl/hmac.h
sess_id.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
sess_id.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
sess_id.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sess_id.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
sess_id.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
sess_id.o: ../include/openssl/rand.h ../include/openssl/rsa.h
sess_id.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sess_id.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
sess_id.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
sess_id.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
sess_id.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
sess_id.o: ../include/openssl/ui.h ../include/openssl/x509.h
sess_id.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
sess_id.o: progs.h sess_id.c
smime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
smime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
smime.o: ../include/openssl/dh.h ../include/openssl/dsa.h
smime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
smime.o: ../include/openssl/engine.h ../include/openssl/err.h
smime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
smime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
smime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
smime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
smime.o: ../include/openssl/pem.h ../include/openssl/pem2.h
smime.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
smime.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
smime.o: ../include/openssl/sha.h ../include/openssl/stack.h
smime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
smime.o: ../include/openssl/ui.h ../include/openssl/x509.h
smime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
smime.o: progs.h smime.c
speed.o: ../e_os.h ../include/openssl/aes.h ../include/openssl/asn1.h
speed.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
speed.o: ../include/openssl/bn.h ../include/openssl/buffer.h
speed.o: ../include/openssl/camellia.h ../include/openssl/cast.h
speed.o: ../include/openssl/conf.h ../include/openssl/crypto.h
speed.o: ../include/openssl/des.h ../include/openssl/dh.h
speed.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
speed.o: ../include/openssl/ec.h ../include/openssl/engine.h
speed.o: ../include/openssl/err.h ../include/openssl/evp.h
speed.o: ../include/openssl/hmac.h ../include/openssl/idea.h
speed.o: ../include/openssl/lhash.h ../include/openssl/md4.h
speed.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
speed.o: ../include/openssl/modes.h ../include/openssl/obj_mac.h
speed.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
speed.o: ../include/openssl/rand.h ../include/openssl/rc2.h
speed.o: ../include/openssl/rc4.h ../include/openssl/ripemd.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/seed.h ../include/openssl/sha.h
speed.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
speed.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
speed.o: ../include/openssl/whrlpool.h ../include/openssl/x509.h
speed.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
speed.o: progs.h speed.c testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/bn.h ../include/openssl/buffer.h
spkac.o: ../include/openssl/conf.h ../include/openssl/crypto.h
spkac.o: ../include/openssl/dh.h ../include/openssl/dsa.h
spkac.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
spkac.o: ../include/openssl/engine.h ../include/openssl/err.h
spkac.o: ../include/openssl/evp.h ../include/openssl/lhash.h
spkac.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
spkac.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
spkac.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
spkac.o: ../include/openssl/pem.h ../include/openssl/pem2.h
spkac.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
spkac.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
spkac.o: ../include/openssl/sha.h ../include/openssl/stack.h
spkac.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
spkac.o: ../include/openssl/ui.h ../include/openssl/x509.h
spkac.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
spkac.o: progs.h spkac.c
srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
srp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
srp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
srp.o: ../include/openssl/dh.h ../include/openssl/dsa.h
srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
srp.o: ../include/openssl/engine.h ../include/openssl/err.h
srp.o: ../include/openssl/evp.h ../include/openssl/lhash.h
srp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
srp.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
srp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
srp.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
srp.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
srp.o: ../include/openssl/sha.h ../include/openssl/srp.h
srp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
srp.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
srp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
srp.o: ../include/openssl/x509v3.h apps.h progs.h srp.c
ts.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ts.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ts.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ts.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ts.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
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
ts.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
ts.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ts.o: ../include/openssl/x509v3.h apps.h progs.h ts.c
verify.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/bn.h ../include/openssl/buffer.h
verify.o: ../include/openssl/conf.h ../include/openssl/crypto.h
verify.o: ../include/openssl/dh.h ../include/openssl/dsa.h
verify.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
verify.o: ../include/openssl/engine.h ../include/openssl/err.h
verify.o: ../include/openssl/evp.h ../include/openssl/lhash.h
verify.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
verify.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
verify.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
verify.o: ../include/openssl/pem.h ../include/openssl/pem2.h
verify.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
verify.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
verify.o: ../include/openssl/sha.h ../include/openssl/stack.h
verify.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
verify.o: ../include/openssl/ui.h ../include/openssl/x509.h
verify.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
verify.o: progs.h verify.c
version.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/dh.h ../include/openssl/dsa.h
version.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
version.o: ../include/openssl/engine.h ../include/openssl/err.h
version.o: ../include/openssl/evp.h ../include/openssl/idea.h
version.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
version.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
version.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
version.o: ../include/openssl/rand.h ../include/openssl/rc4.h
version.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
version.o: ../include/openssl/sha.h ../include/openssl/stack.h
version.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
version.o: ../include/openssl/ui.h ../include/openssl/x509.h
version.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
version.o: progs.h version.c
x509.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/dh.h ../include/openssl/dsa.h
x509.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
x509.o: ../include/openssl/engine.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/lhash.h
x509.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
x509.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
x509.o: ../include/openssl/pem.h ../include/openssl/pem2.h
x509.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
x509.o: ../include/openssl/ui.h ../include/openssl/x509.h
x509.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
x509.o: progs.h x509.c
