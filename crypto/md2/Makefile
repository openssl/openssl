#
# SSLeay/crypto/md/Makefile
#

DIR=	md2
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md2_dgst.c md2_one.c
LIBOBJ=md2_dgst.o md2_one.o

SRC= $(LIBSRC)

EXHEADER= md2.h
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
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@sh $(TOP)/util/point.sh Makefile.ssl Makefile
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

md2_dgst.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md2_dgst.o: ../../include/openssl/md2.h ../../include/openssl/opensslconf.h
md2_dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
md2_dgst.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
md2_dgst.o: md2_dgst.c
md2_one.o: ../../e_os.h ../../include/openssl/bio.h
md2_one.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
md2_one.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
md2_one.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
md2_one.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
md2_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
md2_one.o: ../../include/openssl/symhacks.h ../cryptlib.h md2_one.c
