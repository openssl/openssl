#
# SSLeay/crypto/md5/Makefile
#

DIR=    md5
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=           make -f Makefile.ssl
MAKEDEPEND=     makedepend -f Makefile.ssl
MAKEFILE=       Makefile.ssl
AR=             ar r

MD5_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md5test.c
APPS=md5.c

LIB=$(TOP)/libcrypto.a
LIBSRC=md5_dgst.c md5_one.c
LIBOBJ=md5_dgst.o md5_one.o $(MD5_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= md5.h
HEADER= md5_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

# elf
asm/mx86-elf.o: asm/mx86unix.cpp
	$(CPP) -DELF asm/mx86unix.cpp | as -o asm/mx86-elf.o

# solaris
asm/mx86-sol.o: asm/mx86unix.cpp
	$(CC) -E -DSOL asm/mx86unix.cpp | sed 's/^#.*//' > asm/mx86-sol.s
	as -o asm/mx86-sol.o asm/mx86-sol.s
	rm -f asm/mx86-sol.s

# a.out
asm/mx86-out.o: asm/mx86unix.cpp
	$(CPP) -DOUT asm/mx86unix.cpp | as -o asm/mx86-out.o

# bsdi
asm/mx86bsdi.o: asm/mx86unix.cpp
	$(CPP) -DBSDI asm/mx86unix.cpp | as -o asm/mx86bsdi.o

asm/mx86unix.cpp:
	(cd asm; perl md5-586.pl cpp >mx86unix.cpp)

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
	/bin/rm -f *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

errors:

# DO NOT DELETE THIS LINE -- make depend depends on it.
