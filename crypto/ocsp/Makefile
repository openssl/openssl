#
# OpenSSL/ocsp/Makefile
#

DIR=	ocsp
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= ocsp_asn.c ocsp_ext.c ocsp_ht.c ocsp_lib.c ocsp_cl.c \
	ocsp_srv.c ocsp_prn.c ocsp_vfy.c ocsp_err.c

LIBOBJ= ocsp_asn.o ocsp_ext.o ocsp_ht.o ocsp_lib.o ocsp_cl.o \
	ocsp_srv.o ocsp_prn.o ocsp_vfy.o ocsp_err.o

SRC= $(LIBSRC)

EXHEADER= ocsp.h
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ocsp_asn.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
ocsp_asn.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
ocsp_asn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ocsp_asn.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ocsp_asn.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ocsp_asn.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_asn.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_asn.o: ocsp_asn.c
ocsp_cl.o: ../../e_os.h ../../include/openssl/asn1.h
ocsp_cl.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
ocsp_cl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ocsp_cl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ocsp_cl.o: ../../include/openssl/ocsp.h ../../include/openssl/pem.h
ocsp_cl.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ocsp_cl.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
ocsp_cl.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_cl.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_cl.o: ../cryptlib.h ocsp_cl.c
ocsp_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ocsp_err.o: ../../include/openssl/conf.h ../../include/openssl/err.h
ocsp_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ocsp_err.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ocsp_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ocsp_err.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_err.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_err.o: ocsp_err.c
ocsp_ext.o: ../../e_os.h ../../include/openssl/asn1.h
ocsp_ext.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
ocsp_ext.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ocsp_ext.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ocsp_ext.o: ../../include/openssl/ocsp.h ../../include/openssl/pkcs7.h
ocsp_ext.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
ocsp_ext.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_ext.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_ext.o: ../cryptlib.h ocsp_ext.c
ocsp_ht.o: ../../e_os.h ../../include/openssl/asn1.h
ocsp_ht.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
ocsp_ht.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ocsp_ht.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ocsp_ht.o: ../../include/openssl/ocsp.h ../../include/openssl/pkcs7.h
ocsp_ht.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ocsp_ht.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ocsp_ht.o: ../../include/openssl/x509v3.h ocsp_ht.c
ocsp_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ocsp_lib.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
ocsp_lib.o: ../../include/openssl/conf.h ../../include/openssl/err.h
ocsp_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ocsp_lib.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ocsp_lib.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ocsp_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
ocsp_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ocsp_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ocsp_lib.o: ../../include/openssl/x509v3.h ../cryptlib.h ocsp_lib.c
ocsp_prn.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ocsp_prn.o: ../../include/openssl/conf.h ../../include/openssl/err.h
ocsp_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ocsp_prn.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ocsp_prn.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ocsp_prn.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ocsp_prn.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_prn.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_prn.o: ocsp_prn.c
ocsp_srv.o: ../../e_os.h ../../include/openssl/asn1.h
ocsp_srv.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
ocsp_srv.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ocsp_srv.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ocsp_srv.o: ../../include/openssl/ocsp.h ../../include/openssl/pem.h
ocsp_srv.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ocsp_srv.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
ocsp_srv.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_srv.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_srv.o: ../cryptlib.h ocsp_srv.c
ocsp_vfy.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ocsp_vfy.o: ../../include/openssl/conf.h ../../include/openssl/err.h
ocsp_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ocsp_vfy.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ocsp_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ocsp_vfy.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ocsp_vfy.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ocsp_vfy.o: ocsp_vfy.c
