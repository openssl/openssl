#
# SSLeay/crypto/rc4/Makefile
#

DIR=	rc4
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	makedepend -f Makefile.ssl
MAKEFILE=	Makefile.ssl
AR=		ar r

RC4_ENC=rc4_enc.o
# or use
#RC4_ENC=asm/rx86-elf.o
#RC4_ENC=asm/rx86-out.o
#RC4_ENC=asm/rx86-sol.o
#RC4_ENC=asm/rx86bdsi.o

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=rc4test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc4_skey.c rc4_enc.c
LIBOBJ=rc4_skey.o $(RC4_ENC)

SRC= $(LIBSRC)

EXHEADER= rc4.h
HEADER=	$(EXHEADER) rc4_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

# elf
asm/rx86-elf.o: asm/rx86unix.cpp
	$(CPP) -DELF asm/rx86unix.cpp | as -o asm/rx86-elf.o

# solaris
asm/rx86-sol.o: asm/rx86unix.cpp
	$(CC) -E -DSOL asm/rx86unix.cpp | sed 's/^#.*//' > asm/rx86-sol.s
	as -o asm/rx86-sol.o asm/rx86-sol.s
	rm -f asm/rx86-sol.s

# a.out
asm/rx86-out.o: asm/rx86unix.cpp
	$(CPP) -DOUT asm/rx86unix.cpp | as -o asm/rx86-out.o

# bsdi
asm/rx86bsdi.o: asm/rx86unix.cpp
	$(CPP) -DBSDI asm/rx86unix.cpp | as -o asm/rx86bsdi.o

asm/rx86unix.cpp:
	(cd asm; perl rc4-586.pl cpp >rx86unix.cpp)

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
	$(MAKEDEPEND) $(INCLUDES) $(PROGS) $(LIBSRC)

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	/bin/rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff asm/*.o

errors:

# DO NOT DELETE THIS LINE -- make depend depends on it.
