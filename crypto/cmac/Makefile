#
# OpenSSL/crypto/cmac/Makefile
#

DIR=	cmac
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=cmac.c cm_ameth.c cm_pmeth.c
LIBOBJ=cmac.o cm_ameth.o cm_pmeth.o

SRC= $(LIBSRC)

HEADER=	

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

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cm_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
cm_ameth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cm_ameth.o: ../../include/openssl/buffer.h ../../include/openssl/cmac.h
cm_ameth.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cm_ameth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cm_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cm_ameth.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cm_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cm_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cm_ameth.o: ../../include/openssl/symhacks.h ../include/internal/asn1_int.h
cm_ameth.o: ../include/internal/cryptlib.h cm_ameth.c
cm_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
cm_pmeth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
cm_pmeth.o: ../../include/openssl/buffer.h ../../include/openssl/cmac.h
cm_pmeth.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cm_pmeth.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
cm_pmeth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cm_pmeth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cm_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cm_pmeth.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cm_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cm_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
cm_pmeth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cm_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cm_pmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cm_pmeth.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
cm_pmeth.o: ../include/internal/evp_int.h cm_pmeth.c
cmac.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
cmac.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
cmac.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
cmac.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
cmac.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cmac.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cmac.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cmac.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
cmac.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cmac.o: ../include/internal/cryptlib.h cmac.c
