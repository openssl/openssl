#
# OpenSSL/crypto/md/Makefile
#

DIR=	hmac
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=hmac.c hm_ameth.c hm_pmeth.c
LIBOBJ=hmac.o hm_ameth.o hm_pmeth.o

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

hm_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
hm_ameth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hm_ameth.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
hm_ameth.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
hm_ameth.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
hm_ameth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
hm_ameth.o: ../../include/openssl/opensslconf.h
hm_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hm_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
hm_ameth.o: ../../include/openssl/symhacks.h ../include/internal/asn1_int.h
hm_ameth.o: ../include/internal/cryptlib.h hm_ameth.c
hm_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
hm_pmeth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
hm_pmeth.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
hm_pmeth.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
hm_pmeth.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
hm_pmeth.o: ../../include/openssl/ec.h ../../include/openssl/err.h
hm_pmeth.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
hm_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
hm_pmeth.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
hm_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
hm_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/rsa.h
hm_pmeth.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
hm_pmeth.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hm_pmeth.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
hm_pmeth.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
hm_pmeth.o: ../include/internal/evp_int.h hm_pmeth.c
hmac.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
hmac.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
hmac.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
hmac.o: ../../include/openssl/err.h ../../include/openssl/evp.h
hmac.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
hmac.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
hmac.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
hmac.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
hmac.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
hmac.o: ../include/internal/cryptlib.h hmac.c hmac_lcl.h
