#
#  apps/Makefile
#

INCLUDES_apps=	-I$(TOP_apps) -I../include $(KRB5_INCLUDES)
RM_apps=		rm -f
# KRB5 stuff



CFLAGS_apps= -DMONOLITH $(INCLUDES_apps) $(CFLAG)

GENERAL_apps=Makefile makeapps.com install.com

DLIBCRYPTO_apps=../libcrypto.a
DLIBSSL_apps=../libssl.a
LIBCRYPTO_apps=-L.. -lcrypto
LIBSSL_apps=-L.. -lssl

PROGRAM= openssl

SCRIPTS=CA.sh CA.pl tsget

EXE_apps= $(PROGRAM)$(EXE_EXT)

E_EXE=	verify asn1pars req dgst dh dhparam enc passwd gendh errstr \
	ca crl rsa rsautl dsa dsaparam ec ecparam \
	x509 genrsa gendsa genpkey s_server s_client speed \
	s_time version pkcs7 cms crl2pkcs7 sess_id ciphers nseq pkcs12 \
	pkcs8 pkey pkeyparam pkeyutl spkac smime rand engine ocsp prime ts srp

PROGS_apps= $(PROGRAM).c

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

SRC_apps=$(E_SRC)

EXHEADER_apps=
HEADER_apps=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h \
	$(EXHEADER_apps)

ALL_apps=    $(GENERAL_apps) $(SRC_apps) $(HEADER_apps)


all: all_apps
all_apps:	exe

exe: exe_apps
exe_apps:	$(EXE_apps)

req: sreq.o $(A_OBJ) $(DLIBCRYPTO_apps)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	cat $(TOP_apps)/configure.mk $(TOP_apps)/Makefile.shared | $(MAKE) -f - \
		APPNAME=req OBJECTS="sreq.o $(A_OBJ) $(RAND_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $(LIBCRYPTO_apps) $(EX_LIBS)" \
		link_app.$${shlib_target}

sreq.o: req.c 
	$(CC) -c $(INCLUDES_apps) $(CFLAG) -o sreq.o req.c

files: files_apps
files_apps:
	$(PERL) $(TOP_apps)/util/files.pl TOP=$(TOP_apps) Makefile >> $(TOP_apps)/MINFO

install: install_apps
install_apps:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@set -e; for i in $(EXE_apps); \
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

tags: tags_apps
tags_apps:
	ctags $(SRC_apps)

tests: tests_apps
tests_apps:

links: links_apps
links_apps:

lint: lint_apps
lint_apps:
	lint -DLINT $(INCLUDES_apps) $(SRC_apps)>fluff

dclean: dclean_apps
dclean_apps:
	rm -f CA.pl

clean: clean_apps
clean_apps:
	rm -f *.o *.d *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE_apps)
	rm -f req

$(DLIBSSL_apps):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO_apps):
	(cd ..; $(MAKE) DIRS=crypto all)

$(EXE_apps): progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO_apps) $(DLIBSSL_apps)
	$(RM_apps) $(EXE_apps)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL_apps) $(LIBKRB5) $(LIBCRYPTO_apps)" ; \
	cat $(TOP_apps)/configure.mk $(TOP_apps)/Makefile.shared | $(MAKE) -f - \
		APPNAME=$(EXE_apps) OBJECTS="$(PROGRAM).o $(E_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM_apps) $(PROGRAM).o

.c.o:
	$(CC) $(CFLAGS_apps) $(CPPFLAGS) -c -o $@ $<
