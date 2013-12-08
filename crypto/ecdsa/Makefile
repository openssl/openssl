#
# crypto/ecdsa/Makefile
#

DIR=	ecdsa
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=ecdsatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	ecs_lib.c ecs_asn1.c ecs_ossl.c ecs_sign.c ecs_vrf.c ecs_err.c

LIBOBJ=	ecs_lib.o ecs_asn1.o ecs_ossl.o ecs_sign.o ecs_vrf.o ecs_err.o

SRC= $(LIBSRC)

EXHEADER= ecdsa.h
HEADER=	ecs_locl.h $(EXHEADER)

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
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
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
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ecs_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
ecs_asn1.o: ../../include/openssl/bio.h ../../include/openssl/err.h
ecs_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
ecs_asn1.o: ../../include/openssl/stack.h ecs_asn1.c ecs_locl.h
ecs_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ecs_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ecs_err.o: ecs_err.c
ecs_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
ecs_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecs_lib.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
ecs_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ecs_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ecs_lib.o: ecs_lib.c ecs_locl.h
ecs_ossl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_ossl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ecs_ossl.o: ../../include/openssl/obj_mac.h ../../include/openssl/safestack.h
ecs_ossl.o: ../../include/openssl/stack.h ecs_locl.h ecs_ossl.c
ecs_sign.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_sign.o: ../../include/openssl/engine.h ../../include/openssl/lhash.h
ecs_sign.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ecs_sign.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
ecs_sign.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ecs_sign.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ecs_sign.o: ecs_locl.h ecs_sign.c
ecs_vrf.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecs_vrf.o: ../../include/openssl/engine.h ../../include/openssl/lhash.h
ecs_vrf.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ecs_vrf.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ecs_vrf.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
ecs_vrf.o: ../../include/openssl/x509_vfy.h ecs_locl.h ecs_vrf.c
