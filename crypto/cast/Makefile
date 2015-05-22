#
# OpenSSL/crypto/cast/Makefile
#

DIR=	cast
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CAST_ENC=c_enc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=c_skey.c c_ecb.c c_enc.c c_cfb64.c c_ofb64.c 
LIBOBJ=c_skey.o c_ecb.o $(CAST_ENC) c_cfb64.o c_ofb64.o

SRC= $(LIBSRC)

HEADER=	cast_s.h cast_lcl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

cast-586.s:	asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL)	asm/cast-586.pl $(PERLASM_SCHEME) $(CLAGS) $(PROCESSOR) > $@

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
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

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
c_skey.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
c_skey.o: c_skey.c cast_lcl.h cast_s.h
