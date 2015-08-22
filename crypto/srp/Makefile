DIR=	srp
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=srp_lib.c srp_vfy.c
LIBOBJ=srp_lib.o srp_vfy.o

SRC= $(LIBSRC)

HEADER=	

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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

srp_lib.o: ../../e_os.h ../../include/openssl/asn1.h
srp_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
srp_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
srp_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
srp_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
srp_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
srp_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
srp_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
srp_lib.o: ../../include/openssl/sha.h ../../include/openssl/srp.h
srp_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
srp_lib.o: ../include/internal/bn_srp.h ../include/internal/cryptlib.h
srp_lib.o: srp_lib.c
srp_vfy.o: ../../e_os.h ../../include/openssl/asn1.h
srp_vfy.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
srp_vfy.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
srp_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
srp_vfy.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
srp_vfy.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
srp_vfy.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
srp_vfy.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
srp_vfy.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
srp_vfy.o: ../../include/openssl/srp.h ../../include/openssl/stack.h
srp_vfy.o: ../../include/openssl/symhacks.h ../../include/openssl/txt_db.h
srp_vfy.o: ../include/internal/cryptlib.h srp_vfy.c
