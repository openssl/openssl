#
# OpenSSL/crypto/cast/Makefile
#

DIR=	cast
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

CAST_ENC=c_enc.o
# or use
#CAST_ENC=asm/cx86-elf.o
#CAST_ENC=asm/cx86-out.o
#CAST_ENC=asm/cx86-sol.o
#CAST_ENC=asm/cx86bdsi.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)

GENERAL=Makefile
TEST=casttest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=c_skey.c c_ecb.c c_enc.c c_cfb64.c c_ofb64.c 
LIBOBJ=c_skey.o c_ecb.o $(CAST_ENC) c_cfb64.o c_ofb64.o

SRC= $(LIBSRC)

EXHEADER= cast.h
HEADER=	cast_s.h cast_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

# elf
asm/cx86-elf.s: asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) cast-586.pl elf $(CLAGS) $(PROCESSOR) > cx86-elf.s)

# a.out
asm/cx86-out.o: asm/cx86unix.cpp
	$(CPP) -DOUT asm/cx86unix.cpp | as -o asm/cx86-out.o

# bsdi
asm/cx86bsdi.o: asm/cx86unix.cpp
	$(CPP) -DBSDI asm/cx86unix.cpp | sed 's/ :/:/' | as -o asm/cx86bsdi.o

asm/cx86unix.cpp: asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) cast-586.pl cpp $(PROCESSOR) >cx86unix.cpp)

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
	rm -f asm/cx86unix.cpp asm/*-elf.* *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

c_cfb64.o: ../../e_os.h ../../include/openssl/cast.h
c_cfb64.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_cfb64.o: c_cfb64.c cast_lcl.h
c_ecb.o: ../../e_os.h ../../include/openssl/cast.h
c_ecb.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_ecb.o: ../../include/openssl/opensslv.h c_ecb.c cast_lcl.h
c_enc.o: ../../e_os.h ../../include/openssl/cast.h
c_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_enc.o: c_enc.c cast_lcl.h
c_ofb64.o: ../../e_os.h ../../include/openssl/cast.h
c_ofb64.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_ofb64.o: c_ofb64.c cast_lcl.h
c_skey.o: ../../e_os.h ../../include/openssl/cast.h
c_skey.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
c_skey.o: ../../include/openssl/fips.h ../../include/openssl/opensslconf.h
c_skey.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
c_skey.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
c_skey.o: c_skey.c cast_lcl.h cast_s.h
