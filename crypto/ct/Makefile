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
LIBSRC= ct_lib.c ct_err.c
LIBOBJ= ct_lib.o ct_err.o

SRC= $(LIBSRC)

HEADER=	

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

errors:
	$(PERL) $(TOP)/util/mkerr.pl -conf ct.ec -hprefix internal/ -write *.c

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

ct_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
ct_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
ct_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ct_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ct_err.o: ../../include/openssl/symhacks.h ../include/internal/ct_int.h
ct_err.o: ct_err.c
ct_lib.o: ../../e_os.h ../../include/internal/dane.h
ct_lib.o: ../../include/internal/numbers.h ../../include/openssl/asn1.h
ct_lib.o: ../../include/openssl/async.h ../../include/openssl/bio.h
ct_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ct_lib.o: ../../include/openssl/comp.h ../../include/openssl/crypto.h
ct_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
ct_lib.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
ct_lib.o: ../../include/openssl/ec.h ../../include/openssl/err.h
ct_lib.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
ct_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ct_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_lib.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_lib.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_lib.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_lib.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_lib.o: ../../ssl/packet_locl.h ../../ssl/record/record.h
ct_lib.o: ../../ssl/ssl_locl.h ../../ssl/statem/statem.h
ct_lib.o: ../include/internal/cryptlib.h ../include/internal/ct_int.h ct_lib.c
