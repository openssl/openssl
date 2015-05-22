#
# OpenSSL/crypto/objects/Makefile
#

DIR=	objects
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r
PERL=		perl

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README

LIB=$(TOP)/libcrypto.a
LIBSRC=	o_names.c obj_dat.c obj_lib.c obj_err.c obj_xref.c
LIBOBJ= o_names.o obj_dat.o obj_lib.o obj_err.o obj_xref.o

SRC= $(LIBSRC)

HEADER=	obj_dat.h obj_xref.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	obj_dat.h obj_xref.h lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

obj_dat.h: obj_dat.pl ../../include/openssl/obj_mac.h
	$(PERL) obj_dat.pl ../../include/openssl/obj_mac.h obj_dat.h

# objects.pl both reads and writes obj_mac.num
../../include/openssl/obj_mac.h: objects.pl objects.txt obj_mac.num
	$(PERL) objects.pl objects.txt obj_mac.num ../../include/openssl/obj_mac.h
	@sleep 1; touch ../../include/openssl/obj_mac.h; sleep 1

obj_xref.h: objxref.pl obj_xref.txt obj_mac.num
	$(PERL) objxref.pl obj_mac.num obj_xref.txt > obj_xref.h
	@sleep 1; touch obj_xref.h; sleep 1

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: obj_dat.h ../../include/openssl/obj_mac.h obj_xref.h depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

o_names.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
o_names.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
o_names.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
o_names.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
o_names.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
o_names.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
o_names.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
o_names.o: o_names.c
obj_dat.o: ../../e_os.h ../../include/openssl/asn1.h
obj_dat.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
obj_dat.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
obj_dat.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
obj_dat.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
obj_dat.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
obj_dat.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
obj_dat.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
obj_dat.o: ../../include/openssl/symhacks.h ../include/internal/asn1_int.h
obj_dat.o: ../include/internal/cryptlib.h obj_dat.c obj_dat.h
obj_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
obj_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
obj_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
obj_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
obj_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
obj_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
obj_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
obj_err.o: obj_err.c
obj_lib.o: ../../e_os.h ../../include/openssl/asn1.h
obj_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
obj_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
obj_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
obj_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
obj_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
obj_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
obj_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
obj_lib.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
obj_lib.o: obj_lib.c
obj_xref.o: ../../e_os.h ../../include/openssl/asn1.h
obj_xref.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
obj_xref.o: ../../include/openssl/e_os2.h ../../include/openssl/obj_mac.h
obj_xref.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
obj_xref.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
obj_xref.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
obj_xref.o: ../../include/openssl/symhacks.h obj_xref.c obj_xref.h
