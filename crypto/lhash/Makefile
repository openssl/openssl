#
# OpenSSL/crypto/lhash/Makefile
#

DIR=	lhash
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=lhash.c lh_stats.c
LIBOBJ=lhash.o lh_stats.o

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

lh_stats.o: ../../e_os.h ../../include/openssl/bio.h
lh_stats.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
lh_stats.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
lh_stats.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
lh_stats.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lh_stats.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lh_stats.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
lh_stats.o: lh_stats.c
lhash.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
lhash.o: ../../include/openssl/e_os2.h ../../include/openssl/lhash.h
lhash.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
lhash.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
lhash.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h lhash.c
