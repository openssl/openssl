# Targets
# make          - twidle the options yourself :-)
# make cc       - standard cc options
# make gcc      - standard gcc options
# make x86-elf  - linux-elf etc
# make x86-out  - linux-a.out, FreeBSD etc
# make x86-solaris
# make x86-bdsi

# There are 3 possible performance options, experiment :-)
#OPTS= -DBF_PTR
#OPTS= -DBF_PTR2
OPTS=

DIR=    cast
TOP=    .
CC=     gcc
CFLAG=	-O3 -fomit-frame-pointer

CPP=    $(CC) -E
INCLUDES=
INSTALLTOP=/usr/local/lib
MAKE=           make
MAKEDEPEND=     makedepend
MAKEFILE=       Makefile.uni
AR=             ar r

CAST_ENC=c_enc.o
# or use
#CAST_ENC=asm/cx86-elf.o
#CAST_ENC=asm/cx86-out.o
#CAST_ENC=asm/cx86-sol.o
#CAST_ENC=asm/cx86bdsi.o

CFLAGS= $(OPTS) $(INCLUDES) $(CFLAG) -DFULL_TEST

GENERAL=Makefile
TEST=casttest
APP1=cast_spd
APP2=castopts
APPS=$(APP1) $(APP2)

LIB=libcast.a
LIBSRC=c_skey.c c_ecb.c c_enc.c c_cfb64.c c_ofb64.c
LIBOBJ=c_skey.o c_ecb.o $(CAST_ENC) c_cfb64.o c_ofb64.o

SRC= $(LIBSRC)

EXHEADER= cast.h
HEADER= cast_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

all:    $(LIB) $(TEST) $(APPS)

$(LIB):    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/ranlib.sh $(LIB)
# elf
asm/cx86-elf.o: asm/cx86unix.cpp
	$(CPP) -DELF asm/cx86unix.cpp | as -o asm/cx86-elf.o

# solaris
asm/cx86-sol.o: asm/cx86unix.cpp
	$(CC) -E -DSOL asm/cx86unix.cpp | sed 's/^#.*//' > asm/cx86-sol.s
	as -o asm/cx86-sol.o asm/cx86-sol.s
	rm -f asm/cx86-sol.s

# a.out
asm/cx86-out.o: asm/cx86unix.cpp
	$(CPP) -DOUT asm/cx86unix.cpp | as -o asm/cx86-out.o

# bsdi
asm/cx86bsdi.o: asm/cx86unix.cpp
	$(CPP) -DBSDI asm/cx86unix.cpp | as -o asm/cx86bsdi.o

asm/cx86unix.cpp:
	(cd asm; perl cast-586.pl cpp >cx86unix.cpp)

test:	$(TEST)
	./$(TEST)

$(TEST): $(TEST).c $(LIB)
	$(CC) -o $(TEST) $(CFLAGS) $(TEST).c $(LIB)

$(APP1): $(APP1).c $(LIB)
	$(CC) -o $(APP1) $(CFLAGS) $(APP1).c $(LIB)

$(APP2): $(APP2).c $(LIB)
	$(CC) -o $(APP2) $(CFLAGS) $(APP2).c $(LIB)

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(PROGS) $(LIBSRC)

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	/bin/rm -f $(LIB) $(TEST) $(APPS) *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

cc:
	$(MAKE) CC="cc" CFLAG="-O" all

gcc:
	$(MAKE) CC="gcc" CFLAGS="-O3 -fomit-frame-pointer" all

x86-elf:
	$(MAKE) CAST_ENC="asm/cx86-elf.o" CFLAG="-DELF $(CFLAGS)" all

x86-out:
	$(MAKE) CAST_ENC="asm/cx86-out.o" CFLAG="-DOUT $(CFLAGS)" all

x86-solaris:
	$(MAKE) CAST_ENC="asm/cx86-sol.o" CFLAG="-DSOL $(CFLAGS)" all

x86-bdsi:
	$(MAKE) CAST_ENC="asm/cx86-bdsi.o" CFLAG="-DBDSI $(CFLAGS)" all

# DO NOT DELETE THIS LINE -- make depend depends on it.
