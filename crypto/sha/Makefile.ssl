#
# SSLeay/crypto/sha/Makefile
#

DIR=    sha
TOP=    ../..
CC=     cc
INCLUDES=
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=           make -f Makefile.ssl
MAKEDEPEND=     makedepend -f Makefile.ssl
MAKEFILE=       Makefile.ssl
AR=             ar r

SHA1_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=shatest.c sha1test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=sha_dgst.c sha1dgst.c sha_one.c sha1_one.c
LIBOBJ=sha_dgst.o sha1dgst.o sha_one.o sha1_one.o $(SHA1_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= sha.h
HEADER= sha_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

# elf
asm/sx86-elf.o: asm/sx86unix.cpp
	$(CPP) -DELF asm/sx86unix.cpp | as -o asm/sx86-elf.o

# solaris
asm/sx86-sol.o: asm/sx86unix.cpp
	$(CC) -E -DSOL asm/sx86unix.cpp | sed 's/^#.*//' > asm/sx86-sol.s
	as -o asm/sx86-sol.o asm/sx86-sol.s
	rm -f asm/sx86-sol.s

# a.out
asm/sx86-out.o: asm/sx86unix.cpp
	$(CPP) -DOUT asm/sx86unix.cpp | as -o asm/sx86-out.o

# bsdi
asm/sx86bsdi.o: asm/sx86unix.cpp
	$(CPP) -DBSDI asm/sx86unix.cpp | as -o asm/sx86bsdi.o

asm/sx86unix.cpp:
	(cd asm; perl sha1-586.pl cpp >sx86unix.cpp)

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
