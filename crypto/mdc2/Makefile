#
# OpenSSL/crypto/mdc2/Makefile
#

DIR=	mdc2
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=mdc2dgst.c mdc2_one.c
LIBOBJ=mdc2dgst.o mdc2_one.o

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

mdc2_one.o: ../../e_os.h ../../include/openssl/bio.h
mdc2_one.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
mdc2_one.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
mdc2_one.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
mdc2_one.o: ../../include/openssl/mdc2.h ../../include/openssl/opensslconf.h
mdc2_one.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
mdc2_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
mdc2_one.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
mdc2_one.o: mdc2_one.c
mdc2dgst.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
mdc2dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/mdc2.h
mdc2dgst.o: ../../include/openssl/opensslconf.h
mdc2dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
mdc2dgst.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
mdc2dgst.o: ../../include/openssl/symhacks.h mdc2dgst.c
