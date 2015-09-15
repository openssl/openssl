#
# OpenSSL/crypto/ct/Makefile
#

DIR=	ct
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= ct_lib.c
LIBOBJ= ct_lib.o

SRC= $(LIBSRC)

HEADER=	ct_lcl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update:  depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ct_lib.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ct_lib.o: ../../include/openssl/comp.h ../../include/openssl/crypto.h
ct_lib.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_lib.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
ct_lib.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ct_lib.o: ../../include/openssl/pqueue.h ../../include/openssl/rsa.h
ct_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_lib.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
ct_lib.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl3.h
ct_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_lib.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
ct_lib.o: ../../include/openssl/x509_vfy.h ../../ssl/packet_locl.h
ct_lib.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_lib.o: ../include/internal/cryptlib.h ct_lib.c ct_locl.h
