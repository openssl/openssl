#
# SSLeay/crypto/mdc2/Makefile
#

DIR=	mdc2
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= mdc2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=mdc2dgst.c mdc2_one.c
LIBOBJ=mdc2dgst.o mdc2_one.o

SRC= $(LIBSRC)

EXHEADER= mdc2.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

mdc2_one.o: ../../e_os.h ../../include/openssl/bio.h
mdc2_one.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
mdc2_one.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
mdc2_one.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
mdc2_one.o: ../../include/openssl/lhash.h ../../include/openssl/mdc2.h
mdc2_one.o: ../../include/openssl/opensslconf.h
mdc2_one.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
mdc2_one.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
mdc2_one.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
mdc2_one.o: ../cryptlib.h mdc2_one.c
mdc2dgst.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
mdc2dgst.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
mdc2dgst.o: ../../include/openssl/mdc2.h ../../include/openssl/opensslconf.h
mdc2dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
mdc2dgst.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
mdc2dgst.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
mdc2dgst.o: mdc2dgst.c
