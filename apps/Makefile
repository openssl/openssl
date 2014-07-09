#
#  apps/Makefile
#

DIR=		apps
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES)
RM=		rm -f
# KRB5 stuff



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
	cat $(TOP)/configure.mk $(TOP)/Makefile.shared | $(MAKE) -f - \
		APPNAME=req OBJECTS="sreq.o $(A_OBJ) $(RAND_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS)" \
		link_app.$${shlib_target}

sreq.o: req.c 
	$(CC) -c $(INCLUDES) $(CFLAG) -o sreq.o req.c

files:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

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

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f CA.pl

clean:
	rm -f *.o *.d *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

$(EXE): progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(EXE)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBKRB5) $(LIBCRYPTO)" ; \
	cat $(TOP)/configure.mk $(TOP)/Makefile.shared | $(MAKE) -f - \
		APPNAME=$(EXE) OBJECTS="$(PROGRAM).o $(E_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM) $(PROGRAM).o

