#
# crypto/aes/Makefile
#

DIR=	aes
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=	/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

# CFLAGS= -mpentiumpro $(INCLUDES) $(CFLAG) -O3 -fexpensive-optimizations -funroll-loops -fforce-addr
CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
#TEST=aestest.c
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=aes_core.c aes_misc.c aes_ecb.c aes_cbc.c aes_cfb.c aes_ofb.c aes_ctr.c
LIBOBJ=aes_core.o aes_misc.o aes_ecb.o aes_cbc.o aes_cfb.o aes_ofb.o aes_ctr.o

SRC= $(LIBSRC)

EXHEADER= aes.h
HEADER= aes_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

$(LIBOBJ): $(LIBSRC)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: installs

installs:
	@for i in $(EXHEADER) ; \
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
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

aes_cbc.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_cbc.o: ../../include/openssl/opensslconf.h aes_cbc.c aes_locl.h
aes_cfb.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_cfb.o: ../../include/openssl/opensslconf.h aes_cfb.c aes_locl.h
aes_core.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_core.o: ../../include/openssl/fips.h ../../include/openssl/opensslconf.h
aes_core.o: aes_core.c aes_locl.h
aes_ctr.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_ctr.o: ../../include/openssl/opensslconf.h aes_ctr.c aes_locl.h
aes_ecb.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_ecb.o: ../../include/openssl/opensslconf.h aes_ecb.c aes_locl.h
aes_misc.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_misc.o: ../../include/openssl/opensslconf.h
aes_misc.o: ../../include/openssl/opensslv.h aes_locl.h aes_misc.c
aes_ofb.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_ofb.o: ../../include/openssl/opensslconf.h aes_locl.h aes_ofb.c
