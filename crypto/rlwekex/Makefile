#
# crypto/rlwekex/Makefile
#

DIR=	rlwekex
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=rlwekextest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	rlwekex_key.c rlwekex_err.c

LIBOBJ=	rlwekex_key.o rlwekex_err.o

SRC= $(LIBSRC)

EXHEADER= rlwekex.h
HEADER=	rlwekex_locl.h $(EXHEADER)

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

rlwekex_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rlwekex_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rlwekex_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rlwekex_err.o: ../../include/openssl/opensslconf.h
rlwekex_err.o: ../../include/openssl/opensslv.h
rlwekex_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rlwekex.h
rlwekex_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rlwekex_err.o: ../../include/openssl/symhacks.h rlwekex_err.c
rlwekex_key.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
rlwekex_key.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rlwekex_key.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rlwekex_key.o: ../../include/openssl/opensslconf.h
rlwekex_key.o: ../../include/openssl/opensslv.h
rlwekex_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
rlwekex_key.o: ../../include/openssl/rlwekex.h
rlwekex_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rlwekex_key.o: ../../include/openssl/symhacks.h rlwekexlib/fft.h rlwekexlib/fft.c 
rlwekex_key.o: rlwekexlib/rlwe.h rlwekexlib/rlwe.c rlwekexlib/rlwe_a.h
rlwekex_key.o: rlwekexlib/rlwe_table.h rlwekex_key.c rlwekex_locl.h
