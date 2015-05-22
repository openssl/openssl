DIR=jpake
TOP=../..

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL= Makefile

LIB=$(TOP)/libcrypto.a
LIBOBJ=jpake.o jpake_err.o
LIBSRC=jpake.c jpake_err.c
SRC= $(LIBSRC)

HEADER=

ALL= $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj des lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

jpake.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
jpake.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
jpake.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
jpake.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
jpake.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
jpake.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
jpake.o: ../../include/openssl/symhacks.h jpake.c jpake.h
jpake_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
jpake_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
jpake_err.o: ../../include/openssl/err.h ../../include/openssl/jpake.h
jpake_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
jpake_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
jpake_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
jpake_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
jpake_err.o: jpake_err.c
