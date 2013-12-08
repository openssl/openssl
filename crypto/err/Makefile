#
# OpenSSL/crypto/err/Makefile
#

DIR=	err
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=err.c err_all.c err_prn.c
LIBOBJ=err.o err_all.o err_prn.o

SRC= $(LIBSRC)

EXHEADER= err.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
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
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

err.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
err.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
err.o: ../../include/openssl/stack.h ../cryptlib.h err.c
err_all.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
err_all.o: ../../include/openssl/cms.h ../../include/openssl/comp.h
err_all.o: ../../include/openssl/conf.h ../../include/openssl/dso.h
err_all.o: ../../include/openssl/engine.h ../../include/openssl/err.h
err_all.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
err_all.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
err_all.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs12.h
err_all.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
err_all.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
err_all.o: ../../include/openssl/ts.h ../../include/openssl/ui.h
err_all.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
err_all.o: ../../include/openssl/x509v3.h err_all.c
err_prn.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
err_prn.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
err_prn.o: ../../include/openssl/stack.h ../cryptlib.h err_prn.c
