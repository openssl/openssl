#
#  apps/Makefile.ssl
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I../include
CFLAG=		-g -static
INSTALL_PREFIX=
INSTALLTOP=	/usr/local/ssl
OPENSSLDIR=	/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
PERL=/usr/local/bin/perl
RM=		rm -f

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

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
	pkcs8 spkac smime rand

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
	ciphers.o nseq.o pkcs12.o pkcs8.o spkac.o smime.o rand.o

E_SRC=	verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
	pkcs7.c crl2p7.c crl.c \
	rsa.c rsautl.c dsa.c dsaparam.c \
	x509.c genrsa.c gendsa.c s_server.c s_client.c speed.c \
	s_time.c $(A_SRC) $(S_SRC) $(RAND_SRC) version.c sess_id.c \
	ciphers.c nseq.c pkcs12.c pkcs8.c spkac.c smime.c rand.c

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
	$(CC) -o req $(CFLAG) sreq.o $(A_OBJ) $(RAND_OBJ) $(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS)

sreq.o: req.c 
	$(CC) -c $(INCLUDES) $(CFLAG) -o sreq.o req.c

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

install:
	@for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@for i in $(SCRIPTS); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
	 chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	 done
	@cp openssl.cnf $(INSTALL_PREFIX)$(OPENSSLDIR); \
	chmod 644 $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

tags:
	ctags $(SRC)

tests:

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ../ssl; $(MAKE))

$(DLIBCRYPTO):
	(cd ../crypto; $(MAKE))

$(PROGRAM): progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(PROGRAM)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(PROGRAM).o $(E_OBJ) $(PEX_LIBS) $(LIBSSL) $(LIBCRYPTO) $(EX_LIBS)
	-(cd ..; OPENSSL="`pwd`/apps/openssl"; export OPENSSL; $(PERL) tools/c_rehash certs)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM) $(PROGRAM).o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../include/openssl/asn1.h ../include/openssl/bio.h
app_rand.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
app_rand.o: ../include/openssl/buffer.h ../include/openssl/cast.h
app_rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
app_rand.o: ../include/openssl/des.h ../include/openssl/dh.h
app_rand.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
app_rand.o: ../include/openssl/e_os2.h ../include/openssl/evp.h
app_rand.o: ../include/openssl/idea.h ../include/openssl/lhash.h
app_rand.o: ../include/openssl/md2.h ../include/openssl/md4.h
app_rand.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
app_rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
app_rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
app_rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
app_rand.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
app_rand.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
app_rand.o: ../include/openssl/x509_vfy.h apps.h
apps.o: ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
apps.o: ../include/openssl/buffer.h ../include/openssl/cast.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/des.h ../include/openssl/dh.h
apps.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/err.h
apps.o: ../include/openssl/evp.h ../include/openssl/idea.h
apps.o: ../include/openssl/lhash.h ../include/openssl/md2.h
apps.o: ../include/openssl/md4.h ../include/openssl/md5.h
apps.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
apps.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
apps.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
apps.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
apps.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
apps.o: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
asn1pars.o: ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/cast.h
asn1pars.o: ../include/openssl/conf.h ../include/openssl/crypto.h
asn1pars.o: ../include/openssl/des.h ../include/openssl/dh.h
asn1pars.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
asn1pars.o: ../include/openssl/e_os2.h ../include/openssl/err.h
asn1pars.o: ../include/openssl/evp.h ../include/openssl/idea.h
asn1pars.o: ../include/openssl/lhash.h ../include/openssl/md2.h
asn1pars.o: ../include/openssl/md4.h ../include/openssl/md5.h
asn1pars.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
asn1pars.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
asn1pars.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
asn1pars.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
asn1pars.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
asn1pars.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
asn1pars.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
asn1pars.o: ../include/openssl/sha.h ../include/openssl/stack.h
asn1pars.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
asn1pars.o: ../include/openssl/x509_vfy.h apps.h
ca.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
ca.o: ../include/openssl/buffer.h ../include/openssl/cast.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/des.h ../include/openssl/dh.h ../include/openssl/dsa.h
ca.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
ca.o: ../include/openssl/err.h ../include/openssl/evp.h
ca.o: ../include/openssl/idea.h ../include/openssl/lhash.h
ca.o: ../include/openssl/md2.h ../include/openssl/md4.h
ca.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
ca.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ca.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ca.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ca.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
ca.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
ca.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
ca.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ca.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ca.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ca.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ciphers.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
ciphers.o: ../include/openssl/buffer.h ../include/openssl/cast.h
ciphers.o: ../include/openssl/comp.h ../include/openssl/conf.h
ciphers.o: ../include/openssl/crypto.h ../include/openssl/des.h
ciphers.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ciphers.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/idea.h ../include/openssl/lhash.h
ciphers.o: ../include/openssl/md2.h ../include/openssl/md4.h
ciphers.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
ciphers.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ciphers.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
ciphers.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
ciphers.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
ciphers.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ciphers.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ciphers.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ciphers.o: ../include/openssl/x509_vfy.h apps.h
crl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
crl.o: ../include/openssl/buffer.h ../include/openssl/cast.h
crl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl.o: ../include/openssl/des.h ../include/openssl/dh.h
crl.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
crl.o: ../include/openssl/e_os2.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/idea.h
crl.o: ../include/openssl/lhash.h ../include/openssl/md2.h
crl.o: ../include/openssl/md4.h ../include/openssl/md5.h
crl.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
crl.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
crl.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
crl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
crl.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
crl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
crl.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
crl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
crl2p7.o: ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/cast.h
crl2p7.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl2p7.o: ../include/openssl/des.h ../include/openssl/dh.h
crl2p7.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
crl2p7.o: ../include/openssl/e_os2.h ../include/openssl/err.h
crl2p7.o: ../include/openssl/evp.h ../include/openssl/idea.h
crl2p7.o: ../include/openssl/lhash.h ../include/openssl/md2.h
crl2p7.o: ../include/openssl/md4.h ../include/openssl/md5.h
crl2p7.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
crl2p7.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
crl2p7.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
crl2p7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl2p7.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
crl2p7.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
crl2p7.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
crl2p7.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl2p7.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
crl2p7.o: ../include/openssl/x509_vfy.h apps.h
dgst.o: ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
dgst.o: ../include/openssl/buffer.h ../include/openssl/cast.h
dgst.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dgst.o: ../include/openssl/des.h ../include/openssl/dh.h
dgst.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
dgst.o: ../include/openssl/e_os2.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/idea.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dgst.o: ../include/openssl/md4.h ../include/openssl/md5.h
dgst.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dgst.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
dgst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dgst.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dgst.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dgst.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dgst.o: ../include/openssl/sha.h ../include/openssl/stack.h
dgst.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
dgst.o: ../include/openssl/x509_vfy.h apps.h
dh.o: ../include/openssl/asn1.h ../include/openssl/bio.h
dh.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
dh.o: ../include/openssl/buffer.h ../include/openssl/cast.h
dh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dh.o: ../include/openssl/des.h ../include/openssl/dh.h ../include/openssl/dsa.h
dh.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
dh.o: ../include/openssl/err.h ../include/openssl/evp.h
dh.o: ../include/openssl/idea.h ../include/openssl/lhash.h
dh.o: ../include/openssl/md2.h ../include/openssl/md4.h
dh.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
dh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dh.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dh.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
dh.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
dh.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
dh.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dh.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
dsa.o: ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
dsa.o: ../include/openssl/buffer.h ../include/openssl/cast.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/des.h ../include/openssl/dh.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
dsa.o: ../include/openssl/e_os2.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
dsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
dsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dsa.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
dsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
dsa.o: ../include/openssl/x509_vfy.h apps.h
dsaparam.o: ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
dsaparam.o: ../include/openssl/buffer.h ../include/openssl/cast.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/des.h ../include/openssl/dh.h
dsaparam.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
dsaparam.o: ../include/openssl/e_os2.h ../include/openssl/err.h
dsaparam.o: ../include/openssl/evp.h ../include/openssl/idea.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/md2.h
dsaparam.o: ../include/openssl/md4.h ../include/openssl/md5.h
dsaparam.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dsaparam.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
dsaparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
dsaparam.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
dsaparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
dsaparam.o: ../include/openssl/x509_vfy.h apps.h
enc.o: ../include/openssl/asn1.h ../include/openssl/bio.h
enc.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
enc.o: ../include/openssl/buffer.h ../include/openssl/cast.h
enc.o: ../include/openssl/conf.h ../include/openssl/crypto.h
enc.o: ../include/openssl/des.h ../include/openssl/dh.h
enc.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
enc.o: ../include/openssl/e_os2.h ../include/openssl/err.h
enc.o: ../include/openssl/evp.h ../include/openssl/idea.h
enc.o: ../include/openssl/lhash.h ../include/openssl/md2.h
enc.o: ../include/openssl/md4.h ../include/openssl/md5.h
enc.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
enc.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.o: ../include/openssl/rand.h ../include/openssl/rc2.h
enc.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
enc.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
errstr.o: ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
errstr.o: ../include/openssl/buffer.h ../include/openssl/cast.h
errstr.o: ../include/openssl/comp.h ../include/openssl/conf.h
errstr.o: ../include/openssl/crypto.h ../include/openssl/des.h
errstr.o: ../include/openssl/dh.h ../include/openssl/dsa.h
errstr.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/idea.h ../include/openssl/lhash.h
errstr.o: ../include/openssl/md2.h ../include/openssl/md4.h
errstr.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
errstr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
errstr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
errstr.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
errstr.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
errstr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
errstr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
errstr.o: ../include/openssl/tls1.h ../include/openssl/x509.h
errstr.o: ../include/openssl/x509_vfy.h apps.h
gendh.o: ../include/openssl/asn1.h ../include/openssl/bio.h
gendh.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
gendh.o: ../include/openssl/buffer.h ../include/openssl/cast.h
gendh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendh.o: ../include/openssl/des.h ../include/openssl/dh.h
gendh.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
gendh.o: ../include/openssl/e_os2.h ../include/openssl/err.h
gendh.o: ../include/openssl/evp.h ../include/openssl/idea.h
gendh.o: ../include/openssl/lhash.h ../include/openssl/md2.h
gendh.o: ../include/openssl/md4.h ../include/openssl/md5.h
gendh.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
gendh.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
gendh.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
gendh.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendh.o: ../include/openssl/rand.h ../include/openssl/rc2.h
gendh.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
gendh.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
gendh.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendh.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
gendsa.o: ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
gendsa.o: ../include/openssl/buffer.h ../include/openssl/cast.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/des.h ../include/openssl/dh.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
gendsa.o: ../include/openssl/e_os2.h ../include/openssl/err.h
gendsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
gendsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
gendsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
gendsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
gendsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
gendsa.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
gendsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
gendsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
gendsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendsa.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
gendsa.o: ../include/openssl/x509_vfy.h apps.h
genrsa.o: ../include/openssl/asn1.h ../include/openssl/bio.h
genrsa.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
genrsa.o: ../include/openssl/buffer.h ../include/openssl/cast.h
genrsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genrsa.o: ../include/openssl/des.h ../include/openssl/dh.h
genrsa.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
genrsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
genrsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
genrsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
genrsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
genrsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genrsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
genrsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
genrsa.o: ../include/openssl/x509_vfy.h apps.h
nseq.o: ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
nseq.o: ../include/openssl/buffer.h ../include/openssl/cast.h
nseq.o: ../include/openssl/conf.h ../include/openssl/crypto.h
nseq.o: ../include/openssl/des.h ../include/openssl/dh.h
nseq.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
nseq.o: ../include/openssl/e_os2.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/idea.h
nseq.o: ../include/openssl/lhash.h ../include/openssl/md2.h
nseq.o: ../include/openssl/md4.h ../include/openssl/md5.h
nseq.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
nseq.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
nseq.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
nseq.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
nseq.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
nseq.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
nseq.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
nseq.o: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
nseq.o: ../include/openssl/x509_vfy.h apps.h
openssl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
openssl.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
openssl.o: ../include/openssl/buffer.h ../include/openssl/cast.h
openssl.o: ../include/openssl/comp.h ../include/openssl/conf.h
openssl.o: ../include/openssl/crypto.h ../include/openssl/des.h
openssl.o: ../include/openssl/dh.h ../include/openssl/dsa.h
openssl.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/err.h ../include/openssl/evp.h
openssl.o: ../include/openssl/idea.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/md2.h ../include/openssl/md4.h
openssl.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
openssl.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
openssl.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
openssl.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/x509.h
openssl.o: ../include/openssl/x509_vfy.h apps.h progs.h s_apps.h
passwd.o: ../include/openssl/asn1.h ../include/openssl/bio.h
passwd.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
passwd.o: ../include/openssl/buffer.h ../include/openssl/cast.h
passwd.o: ../include/openssl/conf.h ../include/openssl/crypto.h
passwd.o: ../include/openssl/des.h ../include/openssl/dh.h
passwd.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
passwd.o: ../include/openssl/e_os2.h ../include/openssl/err.h
passwd.o: ../include/openssl/evp.h ../include/openssl/idea.h
passwd.o: ../include/openssl/lhash.h ../include/openssl/md2.h
passwd.o: ../include/openssl/md4.h ../include/openssl/md5.h
passwd.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
passwd.o: ../include/openssl/opensslv.h ../include/openssl/pkcs7.h
passwd.o: ../include/openssl/rand.h ../include/openssl/rc2.h
passwd.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
passwd.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
passwd.o: ../include/openssl/safestack.h ../include/openssl/sha.h
passwd.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
passwd.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
pkcs12.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
pkcs12.o: ../include/openssl/buffer.h ../include/openssl/cast.h
pkcs12.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs12.o: ../include/openssl/des.h ../include/openssl/dh.h
pkcs12.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
pkcs12.o: ../include/openssl/e_os2.h ../include/openssl/err.h
pkcs12.o: ../include/openssl/evp.h ../include/openssl/idea.h
pkcs12.o: ../include/openssl/lhash.h ../include/openssl/md2.h
pkcs12.o: ../include/openssl/md4.h ../include/openssl/md5.h
pkcs12.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
pkcs12.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pkcs12.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
pkcs12.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs12.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
pkcs12.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
pkcs12.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
pkcs12.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs12.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs12.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
pkcs7.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/cast.h
pkcs7.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs7.o: ../include/openssl/des.h ../include/openssl/dh.h
pkcs7.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
pkcs7.o: ../include/openssl/e_os2.h ../include/openssl/err.h
pkcs7.o: ../include/openssl/evp.h ../include/openssl/idea.h
pkcs7.o: ../include/openssl/lhash.h ../include/openssl/md2.h
pkcs7.o: ../include/openssl/md4.h ../include/openssl/md5.h
pkcs7.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
pkcs7.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pkcs7.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
pkcs7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkcs7.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
pkcs7.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
pkcs7.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
pkcs7.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs7.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
pkcs7.o: ../include/openssl/x509_vfy.h apps.h
pkcs8.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/cast.h
pkcs8.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs8.o: ../include/openssl/des.h ../include/openssl/dh.h
pkcs8.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
pkcs8.o: ../include/openssl/e_os2.h ../include/openssl/err.h
pkcs8.o: ../include/openssl/evp.h ../include/openssl/idea.h
pkcs8.o: ../include/openssl/lhash.h ../include/openssl/md2.h
pkcs8.o: ../include/openssl/md4.h ../include/openssl/md5.h
pkcs8.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
pkcs8.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
pkcs8.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
pkcs8.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs8.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
pkcs8.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
pkcs8.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
pkcs8.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs8.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs8.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
rand.o: ../include/openssl/asn1.h ../include/openssl/bio.h
rand.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
rand.o: ../include/openssl/buffer.h ../include/openssl/cast.h
rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.o: ../include/openssl/des.h ../include/openssl/dh.h
rand.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
rand.o: ../include/openssl/e_os2.h ../include/openssl/err.h
rand.o: ../include/openssl/evp.h ../include/openssl/idea.h
rand.o: ../include/openssl/lhash.h ../include/openssl/md2.h
rand.o: ../include/openssl/md4.h ../include/openssl/md5.h
rand.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
rand.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rand.o: ../include/openssl/opensslv.h ../include/openssl/pkcs7.h
rand.o: ../include/openssl/rand.h ../include/openssl/rc2.h
rand.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
rand.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
req.o: ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
req.o: ../include/openssl/buffer.h ../include/openssl/cast.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/des.h ../include/openssl/dh.h
req.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
req.o: ../include/openssl/e_os2.h ../include/openssl/err.h
req.o: ../include/openssl/evp.h ../include/openssl/idea.h
req.o: ../include/openssl/lhash.h ../include/openssl/md2.h
req.o: ../include/openssl/md4.h ../include/openssl/md5.h
req.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
req.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
req.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
req.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
req.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
req.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
req.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.o: ../include/openssl/sha.h ../include/openssl/stack.h
req.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
req.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rsa.o: ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
rsa.o: ../include/openssl/buffer.h ../include/openssl/cast.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/des.h ../include/openssl/dh.h
rsa.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/err.h
rsa.o: ../include/openssl/evp.h ../include/openssl/idea.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/md2.h
rsa.o: ../include/openssl/md4.h ../include/openssl/md5.h
rsa.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsa.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
rsa.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
rsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
rsa.o: ../include/openssl/x509_vfy.h apps.h
rsautl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/cast.h
rsautl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsautl.o: ../include/openssl/des.h ../include/openssl/dh.h
rsautl.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
rsautl.o: ../include/openssl/e_os2.h ../include/openssl/err.h
rsautl.o: ../include/openssl/evp.h ../include/openssl/idea.h
rsautl.o: ../include/openssl/lhash.h ../include/openssl/md2.h
rsautl.o: ../include/openssl/md4.h ../include/openssl/md5.h
rsautl.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
rsautl.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rsautl.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
rsautl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsautl.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
rsautl.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
rsautl.o: ../include/openssl/x509_vfy.h apps.h
s_cb.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_cb.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
s_cb.o: ../include/openssl/buffer.h ../include/openssl/cast.h
s_cb.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_cb.o: ../include/openssl/crypto.h ../include/openssl/des.h
s_cb.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_cb.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
s_cb.o: ../include/openssl/err.h ../include/openssl/evp.h
s_cb.o: ../include/openssl/idea.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/md2.h ../include/openssl/md4.h
s_cb.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_cb.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
s_cb.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
s_cb.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
s_cb.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_cb.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_cb.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_cb.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s_cb.o: ../include/openssl/x509_vfy.h apps.h s_apps.h
s_client.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_client.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
s_client.o: ../include/openssl/buffer.h ../include/openssl/cast.h
s_client.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_client.o: ../include/openssl/crypto.h ../include/openssl/des.h
s_client.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_client.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/idea.h ../include/openssl/lhash.h
s_client.o: ../include/openssl/md2.h ../include/openssl/md4.h
s_client.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
s_client.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_client.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_client.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_client.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_client.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_client.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_client.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_client.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_client.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
s_client.o: s_apps.h
s_server.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_server.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
s_server.o: ../include/openssl/buffer.h ../include/openssl/cast.h
s_server.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_server.o: ../include/openssl/crypto.h ../include/openssl/des.h
s_server.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_server.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
s_server.o: ../include/openssl/err.h ../include/openssl/evp.h
s_server.o: ../include/openssl/idea.h ../include/openssl/lhash.h
s_server.o: ../include/openssl/md2.h ../include/openssl/md4.h
s_server.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
s_server.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_server.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_server.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_server.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_server.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_server.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_server.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_server.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
s_server.o: s_apps.h
s_socket.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
s_socket.o: ../include/openssl/buffer.h ../include/openssl/cast.h
s_socket.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/des.h
s_socket.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_socket.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
s_socket.o: ../include/openssl/evp.h ../include/openssl/idea.h
s_socket.o: ../include/openssl/lhash.h ../include/openssl/md2.h
s_socket.o: ../include/openssl/md4.h ../include/openssl/md5.h
s_socket.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
s_socket.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
s_socket.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_socket.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
s_socket.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
s_socket.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_socket.o: ../include/openssl/sha.h ../include/openssl/ssl.h
s_socket.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_socket.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
s_socket.o: s_apps.h
s_time.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
s_time.o: ../include/openssl/buffer.h ../include/openssl/cast.h
s_time.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_time.o: ../include/openssl/crypto.h ../include/openssl/des.h
s_time.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s_time.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/idea.h ../include/openssl/lhash.h
s_time.o: ../include/openssl/md2.h ../include/openssl/md4.h
s_time.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
s_time.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_time.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
s_time.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
s_time.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
s_time.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_time.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_time.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s_time.o: ../include/openssl/x509_vfy.h apps.h s_apps.h
sess_id.o: ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
sess_id.o: ../include/openssl/buffer.h ../include/openssl/cast.h
sess_id.o: ../include/openssl/comp.h ../include/openssl/conf.h
sess_id.o: ../include/openssl/crypto.h ../include/openssl/des.h
sess_id.o: ../include/openssl/dh.h ../include/openssl/dsa.h
sess_id.o: ../include/openssl/e_os.h ../include/openssl/e_os2.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/idea.h ../include/openssl/lhash.h
sess_id.o: ../include/openssl/md2.h ../include/openssl/md4.h
sess_id.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
sess_id.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sess_id.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
sess_id.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
sess_id.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
sess_id.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
sess_id.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
sess_id.o: ../include/openssl/tls1.h ../include/openssl/x509.h
sess_id.o: ../include/openssl/x509_vfy.h apps.h
smime.o: ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
smime.o: ../include/openssl/buffer.h ../include/openssl/cast.h
smime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
smime.o: ../include/openssl/des.h ../include/openssl/dh.h
smime.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
smime.o: ../include/openssl/e_os2.h ../include/openssl/err.h
smime.o: ../include/openssl/evp.h ../include/openssl/idea.h
smime.o: ../include/openssl/lhash.h ../include/openssl/md2.h
smime.o: ../include/openssl/md4.h ../include/openssl/md5.h
smime.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
smime.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
smime.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
smime.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
smime.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
smime.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
smime.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
smime.o: ../include/openssl/sha.h ../include/openssl/stack.h
smime.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
smime.o: ../include/openssl/x509_vfy.h apps.h
speed.o: ../include/openssl/asn1.h ../include/openssl/bio.h
speed.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
speed.o: ../include/openssl/buffer.h ../include/openssl/cast.h
speed.o: ../include/openssl/conf.h ../include/openssl/crypto.h
speed.o: ../include/openssl/des.h ../include/openssl/dh.h
speed.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
speed.o: ../include/openssl/e_os2.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.o: ../include/openssl/idea.h ../include/openssl/lhash.h
speed.o: ../include/openssl/md2.h ../include/openssl/md4.h
speed.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
speed.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
speed.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/sha.h ../include/openssl/stack.h
speed.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
speed.o: ../include/openssl/x509_vfy.h ./testdsa.h ./testrsa.h apps.h
spkac.o: ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/cast.h
spkac.o: ../include/openssl/conf.h ../include/openssl/crypto.h
spkac.o: ../include/openssl/des.h ../include/openssl/dh.h
spkac.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
spkac.o: ../include/openssl/e_os2.h ../include/openssl/err.h
spkac.o: ../include/openssl/evp.h ../include/openssl/idea.h
spkac.o: ../include/openssl/lhash.h ../include/openssl/md2.h
spkac.o: ../include/openssl/md4.h ../include/openssl/md5.h
spkac.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
spkac.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
spkac.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
spkac.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
spkac.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
spkac.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
spkac.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
spkac.o: ../include/openssl/sha.h ../include/openssl/stack.h
spkac.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
spkac.o: ../include/openssl/x509_vfy.h apps.h
verify.o: ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
verify.o: ../include/openssl/buffer.h ../include/openssl/cast.h
verify.o: ../include/openssl/conf.h ../include/openssl/crypto.h
verify.o: ../include/openssl/des.h ../include/openssl/dh.h
verify.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
verify.o: ../include/openssl/e_os2.h ../include/openssl/err.h
verify.o: ../include/openssl/evp.h ../include/openssl/idea.h
verify.o: ../include/openssl/lhash.h ../include/openssl/md2.h
verify.o: ../include/openssl/md4.h ../include/openssl/md5.h
verify.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
verify.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
verify.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
verify.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
verify.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
verify.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
verify.o: ../include/openssl/sha.h ../include/openssl/stack.h
verify.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
verify.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
version.o: ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/cast.h
version.o: ../include/openssl/conf.h ../include/openssl/crypto.h
version.o: ../include/openssl/des.h ../include/openssl/dh.h
version.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
version.o: ../include/openssl/e_os2.h ../include/openssl/evp.h
version.o: ../include/openssl/idea.h ../include/openssl/lhash.h
version.o: ../include/openssl/md2.h ../include/openssl/md4.h
version.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
version.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
version.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
version.o: ../include/openssl/pkcs7.h ../include/openssl/rc2.h
version.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
version.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
version.o: ../include/openssl/safestack.h ../include/openssl/sha.h
version.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
version.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h apps.h
x509.o: ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
x509.o: ../include/openssl/buffer.h ../include/openssl/cast.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/des.h ../include/openssl/dh.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os.h
x509.o: ../include/openssl/e_os2.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/idea.h
x509.o: ../include/openssl/lhash.h ../include/openssl/md2.h
x509.o: ../include/openssl/md4.h ../include/openssl/md5.h
x509.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
x509.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
x509.o: ../include/openssl/opensslv.h ../include/openssl/pem.h
x509.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
x509.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
x509.o: ../include/openssl/rc5.h ../include/openssl/ripemd.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
x509.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
