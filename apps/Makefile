#
#  apps/Makefile
#

INCLUDES_apps=	-I. -Iinclude $(KRB5_INCLUDES)
RM_apps=		rm -f
# KRB5 stuff



CFLAGS_apps= -DMONOLITH $(INCLUDES_apps) $(CFLAG)

GENERAL_apps=apps/Makefile apps/makeapps.com apps/install.com

DLIBCRYPTO_apps=libcrypto.a
DLIBSSL_apps=libssl.a
LIBCRYPTO_apps=-L. -lcrypto
LIBSSL_apps=-L. -lssl

PROGRAM= apps/openssl

SCRIPTS=apps/CA.sh apps/CA.pl apps/tsget

EXE_apps= $(PROGRAM)$(EXE_EXT)

E_EXE=	apps/verify apps/asn1pars apps/req apps/dgst apps/dh apps/dhparam apps/enc apps/passwd apps/gendh apps/errstr \
	apps/ca apps/crl apps/rsa apps/rsautl apps/dsa apps/dsaparam apps/ec apps/ecparam \
	apps/x509 apps/genrsa apps/gendsa apps/genpkey apps/s_server apps/s_client apps/speed \
	apps/s_time apps/version apps/pkcs7 apps/cms apps/crl2pkcs7 apps/sess_id apps/ciphers apps/nseq apps/pkcs12 \
	apps/pkcs8 apps/pkey apps/pkeyparam apps/pkeyutl apps/spkac apps/smime apps/rand apps/engine apps/ocsp apps/prime apps/ts apps/srp

PROGS_apps= $(PROGRAM).c

A_OBJ=apps/apps.o
A_SRC=apps/apps.c
S_OBJ=	apps/s_cb.o apps/s_socket.o
S_SRC=	apps/s_cb.c apps/s_socket.c
RAND_OBJ=apps/app_rand.o
RAND_SRC=apps/app_rand.c

E_OBJ=	apps/verify.o apps/asn1pars.o apps/req.o apps/dgst.o apps/dh.o apps/dhparam.o apps/enc.o apps/passwd.o apps/gendh.o apps/errstr.o \
	apps/ca.o apps/pkcs7.o apps/crl2p7.o apps/crl.o \
	apps/rsa.o apps/rsautl.o apps/dsa.o apps/dsaparam.o apps/ec.o apps/ecparam.o \
	apps/x509.o apps/genrsa.o apps/gendsa.o apps/genpkey.o apps/s_server.o apps/s_client.o apps/speed.o \
	apps/s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) apps/version.o apps/sess_id.o \
	apps/ciphers.o apps/nseq.o apps/pkcs12.o apps/pkcs8.o apps/pkey.o apps/pkeyparam.o apps/pkeyutl.o \
	apps/spkac.o apps/smime.o apps/cms.o apps/rand.o apps/engine.o apps/ocsp.o apps/prime.o apps/ts.o apps/srp.o

E_SRC=	apps/verify.c apps/asn1pars.c apps/req.c apps/dgst.c apps/dh.c apps/enc.c apps/passwd.c apps/gendh.c apps/errstr.c apps/ca.c \
	apps/pkcs7.c apps/crl2p7.c apps/crl.c \
	apps/rsa.c apps/rsautl.c apps/dsa.c apps/dsaparam.c apps/ec.c apps/ecparam.c \
	apps/x509.c apps/genrsa.c apps/gendsa.c apps/genpkey.c apps/s_server.c apps/s_client.c apps/speed.c \
	apps/s_time.c $(A_SRC) $(S_SRC) $(RAND_SRC) apps/version.c apps/sess_id.c \
	apps/ciphers.c apps/nseq.c apps/pkcs12.c apps/pkcs8.c apps/pkey.c apps/pkeyparam.c apps/pkeyutl.c \
	apps/spkac.c apps/smime.c apps/cms.c apps/rand.c apps/engine.c apps/ocsp.c apps/prime.c apps/ts.c apps/srp.c

SRC_apps=$(E_SRC)

EXHEADER_apps=
HEADER_apps=	apps/apps.h apps/progs.h apps/s_apps.h \
	apps/testdsa.h apps/testrsa.h \
	$(EXHEADER_apps)

ALL_apps=    $(GENERAL_apps) $(SRC_apps) $(HEADER_apps)


all: all_apps
all_apps:	exe_apps

exe: exe_apps
exe_apps:	$(EXE_apps)

apps/req: apps/sreq.o $(A_OBJ) $(DLIBCRYPTO_apps)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	cat configure.mk Makefile.shared | $(MAKE) -f - \
		APPNAME=apps/req OBJECTS=apps/"sreq.o $(A_OBJ) $(RAND_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $(LIBCRYPTO_apps) $(EX_LIBS)" \
		link_app.$${shlib_target}

apps/sreq.o: apps/req.c 
	$(CC) -c $(INCLUDES_apps) $(CFLAG) -o apps/sreq.o apps/req.c

files: files_apps
files_apps:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

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
	lint -DLINT $(INCLUDES_apps) $(SRC_apps)>apps/fluff

dclean: dclean_apps
dclean_apps:
	rm -f apps/CA.pl

clean: clean_apps
clean_apps:
	rm -f apps/*.o apps/*.d apps/*.obj apps/*.dll apps/lib apps/tags apps/core apps/.pure apps/.nfs* apps/*.old apps/*.bak apps/fluff $(EXE_apps)
	rm -f apps/req

$(DLIBSSL_apps):
	(cd apps/..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO_apps):
	(cd apps/..; $(MAKE) DIRS=crypto all)

$(EXE_apps): apps/progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO_apps) $(DLIBSSL_apps)
	$(RM_apps) $(EXE_apps)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL_apps) $(LIBKRB5) $(LIBCRYPTO_apps)" ; \
	cat configure.mk Makefile.shared | $(MAKE) -f - \
		APPNAME=$(EXE_apps) OBJECTS=apps/"$(PROGRAM).o $(E_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd apps/..; $(MAKE) rehash)

apps/progs.h: apps/progs.pl
	$(PERL) apps/progs.pl $(E_EXE) >apps/progs.h
	$(RM_apps) $(PROGRAM).o

.c.o:
	$(CC) $(CFLAGS_apps) $(CPPFLAGS) -c -o $@ $<
