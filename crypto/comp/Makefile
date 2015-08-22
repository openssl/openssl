#
# OpenSSL/crypto/comp/Makefile
#

DIR=	comp
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= comp_lib.c comp_err.c \
	c_zlib.c

LIBOBJ=	comp_lib.o comp_err.o \
	c_zlib.o

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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

c_zlib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
c_zlib.o: ../../include/openssl/comp.h ../../include/openssl/crypto.h
c_zlib.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
c_zlib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
c_zlib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
c_zlib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
c_zlib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
c_zlib.o: ../../include/openssl/symhacks.h c_zlib.c comp_lcl.h
comp_err.o: ../../include/openssl/bio.h ../../include/openssl/comp.h
comp_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
comp_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
comp_err.o: ../../include/openssl/opensslconf.h
comp_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
comp_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
comp_err.o: ../../include/openssl/symhacks.h comp_err.c
comp_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
comp_lib.o: ../../include/openssl/comp.h ../../include/openssl/crypto.h
comp_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/obj_mac.h
comp_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
comp_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
comp_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
comp_lib.o: ../../include/openssl/symhacks.h comp_lcl.h comp_lib.c
