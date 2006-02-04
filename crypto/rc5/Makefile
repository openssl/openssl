#
# OpenSSL/crypto/rc5/Makefile
#

DIR=	rc5
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

RC5_ENC=		rc5_enc.o
# or use
#DES_ENC=	r586-elf.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)

GENERAL=Makefile
TEST=rc5test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc5_skey.c rc5_ecb.c rc5_enc.c rc5cfb64.c rc5ofb64.c 
LIBOBJ=rc5_skey.o rc5_ecb.o $(RC5_ENC) rc5cfb64.o rc5ofb64.o

SRC= $(LIBSRC)

EXHEADER= rc5.h
HEADER=	rc5_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

# elf
asm/r586-elf.s: asm/rc5-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) rc5-586.pl elf $(CFLAGS) > r586-elf.s)

# a.out
asm/r586-out.o: asm/r586unix.cpp
	$(CPP) -DOUT asm/r586unix.cpp | as -o asm/r586-out.o

# bsdi
asm/r586bsdi.o: asm/r586unix.cpp
	$(CPP) -DBSDI asm/r586unix.cpp | sed 's/ :/:/' | as -o asm/r586bsdi.o

asm/r586unix.cpp: asm/rc5-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) rc5-586.pl cpp >r586unix.cpp)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f asm/r586unix.cpp asm/*-elf.* *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

rc5_ecb.o: ../../include/openssl/opensslv.h ../../include/openssl/rc5.h
rc5_ecb.o: rc5_ecb.c rc5_locl.h
rc5_enc.o: ../../include/openssl/rc5.h rc5_enc.c rc5_locl.h
rc5_skey.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rc5_skey.o: ../../include/openssl/fips.h ../../include/openssl/opensslconf.h
rc5_skey.o: ../../include/openssl/opensslv.h ../../include/openssl/rc5.h
rc5_skey.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rc5_skey.o: ../../include/openssl/symhacks.h rc5_locl.h rc5_skey.c
rc5cfb64.o: ../../include/openssl/rc5.h rc5_locl.h rc5cfb64.c
rc5ofb64.o: ../../include/openssl/rc5.h rc5_locl.h rc5ofb64.c
