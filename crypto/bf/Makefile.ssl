#
# SSLeay/crypto/blowfish/Makefile
#

DIR=	bf
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	makedepend -f Makefile.ssl
MAKEFILE=	Makefile.ssl
AR=		ar r

BF_ENC=		bf_enc.o
# or use
#DES_ENC=	bx86-elf.o

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=bftest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=bf_skey.c bf_ecb.c bf_enc.c bf_cfb64.c bf_ofb64.c 
LIBOBJ=bf_skey.o bf_ecb.o $(BF_ENC) bf_cfb64.o bf_ofb64.o

SRC= $(LIBSRC)

EXHEADER= blowfish.h
HEADER=	bf_pi.h bf_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

# elf
asm/bx86-elf.o: asm/bx86unix.cpp
	$(CPP) -DELF asm/bx86unix.cpp | as -o asm/bx86-elf.o

# solaris
asm/bx86-sol.o: asm/bx86unix.cpp
	$(CC) -E -DSOL asm/bx86unix.cpp | sed 's/^#.*//' > asm/bx86-sol.s
	as -o asm/bx86-sol.o asm/bx86-sol.s
	rm -f asm/bx86-sol.s

# a.out
asm/bx86-out.o: asm/bx86unix.cpp
	$(CPP) -DOUT asm/bx86unix.cpp | as -o asm/bx86-out.o

# bsdi
asm/bx86bsdi.o: asm/bx86unix.cpp
	$(CPP) -DBSDI asm/bx86unix.cpp | as -o asm/bx86bsdi.o

asm/bx86unix.cpp:
	(cd asm; perl bf-586.pl cpp >bx86unix.cpp)

files:
	perl $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	/bin/rm -f Makefile
	$(TOP)/util/point.sh Makefile.ssl Makefile ;
	$(TOP)/util/point.sh ../../doc/blowfish.doc blowfish.doc ;
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
	$(MAKEDEPEND) $(INCLUDES) $(PROGS) $(LIBSRC)

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	/bin/rm -f *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

errors:

# DO NOT DELETE THIS LINE -- make depend depends on it.
