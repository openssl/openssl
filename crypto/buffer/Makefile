#
# OpenSSL/crypto/buffer/Makefile
#

DIR=	buffer
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= buffer.c buf_str.c buf_err.c
LIBOBJ= buffer.o buf_str.o buf_err.o

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

buf_err.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
buf_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
buf_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
buf_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
buf_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
buf_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
buf_err.o: buf_err.c
buf_str.o: ../../e_os.h ../../include/openssl/bio.h
buf_str.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
buf_str.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
buf_str.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
buf_str.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
buf_str.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
buf_str.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
buf_str.o: buf_str.c
buffer.o: ../../e_os.h ../../include/openssl/bio.h
buffer.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
buffer.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
buffer.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
buffer.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
buffer.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
buffer.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
buffer.o: buffer.c
