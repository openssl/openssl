#
# SSLeay/crypto/md4/Makefile
#

DIR=    md4
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=           make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=       Makefile.ssl
AR=             ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md4test.c
APPS=md4.c

LIB=$(TOP)/libcrypto.a
LIBSRC=md4_dgst.c md4_one.c
LIBOBJ=md4_dgst.o md4_one.o

SRC= $(LIBSRC)

EXHEADER= md4.h
HEADER= md4_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	@echo You may get an error following this line.  Please ignore.
	- $(RANLIB) $(LIB)
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
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
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f asm/mx86unix.cpp *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

md4_dgst.o: ../../include/openssl/md4.h ../../include/openssl/opensslconf.h
md4_dgst.o: ../../include/openssl/opensslv.h ../md32_common.h md4_locl.h
md4_one.o: ../../include/openssl/md4.h
