#
# OpenSSL/crypto/rand/Makefile
#

DIR=	rand
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=md_rand.c randfile.c rand_lib.c rand_err.c rand_egd.c \
	rand_win.c rand_unix.c rand_os2.c rand_nw.c
LIBOBJ=md_rand.o randfile.o rand_lib.o rand_err.o rand_egd.o \
	rand_win.o rand_unix.o rand_os2.o rand_nw.o

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

md_rand.o: ../../e_os.h ../../include/openssl/asn1.h
md_rand.o: ../../include/openssl/async.h ../../include/openssl/bio.h
md_rand.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
md_rand.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
md_rand.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
md_rand.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
md_rand.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
md_rand.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
md_rand.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
md_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
md_rand.o: md_rand.c rand_lcl.h
rand_egd.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rand_egd.o: ../../include/openssl/opensslconf.h
rand_egd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_egd.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_egd.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_egd.o: rand_egd.c
rand_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
rand_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
rand_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_err.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_err.o: rand_err.c
rand_lib.o: ../../e_os.h ../../include/openssl/asn1.h
rand_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rand_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_lib.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
rand_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
rand_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
rand_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_lib.o: ../../include/openssl/opensslconf.h
rand_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
rand_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
rand_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
rand_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rand_lib.o: ../include/internal/cryptlib.h rand_lib.c
rand_nw.o: ../../e_os.h ../../include/openssl/asn1.h
rand_nw.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rand_nw.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_nw.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_nw.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_nw.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_nw.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rand_nw.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
rand_nw.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
rand_nw.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_nw.o: ../include/internal/cryptlib.h rand_lcl.h rand_nw.c
rand_os2.o: ../../e_os.h ../../include/openssl/asn1.h
rand_os2.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rand_os2.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_os2.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_os2.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_os2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_os2.o: ../../include/openssl/opensslconf.h
rand_os2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_os2.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_os2.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_os2.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
rand_os2.o: rand_lcl.h rand_os2.c
rand_unix.o: ../../e_os.h ../../include/openssl/asn1.h
rand_unix.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rand_unix.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_unix.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_unix.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_unix.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_unix.o: ../../include/openssl/opensslconf.h
rand_unix.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_unix.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_unix.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_unix.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
rand_unix.o: rand_lcl.h rand_unix.c
rand_win.o: ../../e_os.h ../../include/openssl/asn1.h
rand_win.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rand_win.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_win.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_win.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_win.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_win.o: ../../include/openssl/opensslconf.h
rand_win.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_win.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_win.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_win.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
rand_win.o: rand_lcl.h rand_win.c
randfile.o: ../../e_os.h ../../include/openssl/buffer.h
randfile.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
randfile.o: ../../include/openssl/opensslconf.h
randfile.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
randfile.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
randfile.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
randfile.o: randfile.c
