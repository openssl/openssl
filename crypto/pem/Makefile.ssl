#
# SSLeay/crypto/pem/Makefile
#

DIR=	pem
TOP=	../..
CC=	cc
INCLUDES= -I.. -I../../include
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	makedepend -f Makefile.ssl
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

ERR=pem
ERRC=pem_err
GENERAL=Makefile
TEST=
APPS=

CTX_SIZE= ctx_size

LIB=$(TOP)/libcrypto.a
LIBSRC= pem_sign.c pem_seal.c pem_info.c pem_lib.c pem_all.c $(ERRC).c

LIBOBJ=	pem_sign.o pem_seal.o pem_info.o pem_lib.o pem_all.o $(ERRC).o

SRC= $(LIBSRC)

EXHEADER= pem.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	pem.h lib

pem.h: $(CTX_SIZE)
	./$(CTX_SIZE) <pem.org >pem.new
	if [ -f pem.h ]; then mv -f pem.h pem.old; fi
	mv -f pem.new pem.h

$(CTX_SIZE): $(CTX_SIZE).o
	$(CC) $(CFLAGS) -o $(CTX_SIZE) $(CTX_SIZE).o

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

files:
	perl $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	/bin/rm -f Makefile
	$(TOP)/util/point.sh Makefile.ssl Makefile ;
	$(TOP)/util/mklink.sh ../../include $(EXHEADER)
	$(TOP)/util/mklink.sh ../../test $(TEST)
	$(TOP)/util/mklink.sh ../../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALLTOP)/include/$$i; \
	chmod 644 $(INSTALLTOP)/include/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(CTX_SIZE).c $(LIBSRC)

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	/bin/rm -f $(CTX_SIZE) *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

errors:
	perl $(TOP)/util/err-ins.pl $(ERR).err $(ERR).org # SPECIAL CASE .org
	perl $(TOP)/util/err-ins.pl $(ERR).err $(ERR).h
	perl ../err/err_genc.pl -s $(ERR).h $(ERRC).c

# DO NOT DELETE THIS LINE -- make depend depends on it.
