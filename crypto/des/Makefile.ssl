#
# SSLeay/crypto/des/Makefile
#

DIR=	des
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
DES_ENC=	des_enc.o fcrypt_b.o
# or use
#DES_ENC=	dx86-elf.o cx86-elf.o

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile des.org des_locl.org
TEST=destest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	cbc3_enc.c cbc_cksm.c cbc_enc.c  cfb64enc.c cfb_enc.c  \
	ecb3_enc.c ecb_enc.c  ede_enc.c  enc_read.c enc_writ.c \
	fcrypt.c   ncbc_enc.c ofb64enc.c ofb_enc.c  pcbc_enc.c \
	qud_cksm.c rand_key.c read_pwd.c rpc_enc.c  set_key.c  \
	des_enc.c fcrypt_b.c read2pwd.c \
	fcrypt.c xcbc_enc.c \
	str2key.c  cfb64ede.c ofb64ede.c supp.c

LIBOBJ= set_key.o  ecb_enc.o  ede_enc.o  cbc_enc.o  cbc3_enc.o \
	ecb3_enc.o cfb64enc.o cfb64ede.o cfb_enc.o  ofb64ede.o \
	enc_read.o enc_writ.o ncbc_enc.o ofb64enc.o \
	ofb_enc.o  str2key.o  pcbc_enc.o qud_cksm.o rand_key.o \
	${DES_ENC} read2pwd.o \
	fcrypt.o xcbc_enc.o read_pwd.o rpc_enc.o  cbc_cksm.o supp.o

SRC= $(LIBSRC)

EXHEADER= des.h
HEADER=	des_locl.h rpc_des.h podd.h sk.h spr.h des_ver.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

# elf
asm/dx86-elf.o: asm/dx86-cpp.s asm/dx86unix.cpp
	$(CPP) -DELF asm/dx86unix.cpp | as -o asm/dx86-elf.o

asm/cx86-elf.o: asm/cx86-cpp.s asm/cx86unix.cpp
	$(CPP) -DELF asm/cx86unix.cpp | as -o asm/cx86-elf.o

# solaris
asm/dx86-sol.o: asm/dx86-cpp.s asm/dx86unix.cpp
	$(CC) -E -DSOL asm/dx86unix.cpp | sed 's/^#.*//' > asm/dx86-sol.s
	as -o asm/dx86-sol.o asm/dx86-sol.s
	rm -f asm/dx86-sol.s

asm/cx86-sol.o: asm/cx86-cpp.s asm/cx86unix.cpp
	$(CC) -E -DSOL asm/cx86unix.cpp | sed 's/^#.*//' > asm/cx86-sol.s
	as -o asm/cx86-sol.o asm/cx86-sol.s
	rm -f asm/cx86-sol.s

# a.out
asm/dx86-out.o: asm/dx86-cpp.s asm/dx86unix.cpp
	$(CPP) -DOUT asm/dx86unix.cpp | as -o asm/dx86-out.o

asm/cx86-out.o: asm/cx86-cpp.s asm/cx86unix.cpp
	$(CPP) -DOUT asm/cx86unix.cpp | as -o asm/cx86-out.o

# bsdi
asm/dx86bsdi.o: asm/dx86-cpp.s asm/dx86unix.cpp
	$(CPP) -DBSDI asm/dx86unix.cpp | as -o asm/dx86bsdi.o

asm/cx86bsdi.o: asm/cx86-cpp.s asm/cx86unix.cpp
	$(CPP) -DBSDI asm/cx86unix.cpp | as -o asm/cx86bsdi.o

files:
	perl $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	/bin/rm -f Makefile
	$(TOP)/util/point.sh Makefile.ssl Makefile
	/bin/rm -f des.doc
	$(TOP)/util/point.sh ../../doc/des.doc des.doc
	$(TOP)/util/mklink.sh ../../include $(EXHEADER)
	$(TOP)/util/mklink.sh ../../test $(TEST)
	$(TOP)/util/mklink.sh ../../apps $(APPS)
	/bin/rm -f asm/x86ms.pl asm/x86unix.pl
	$(TOP)/util/point.sh ../../perlasm/x86ms.pl asm/x86ms.pl
	$(TOP)/util/point.sh ../../perlasm/x86unix.pl asm/x86unix.pl

install: installs

installs:
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
