#
# SSLeay/crypto/rand/Makefile
#

DIR=	rand
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= randtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md_rand.c randfile.c rand_lib.c rand_err.c rand_egd.c rand_win.c
LIBOBJ=md_rand.o randfile.o rand_lib.o rand_err.o rand_egd.o rand_win.o

SRC= $(LIBSRC)

EXHEADER= rand.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB)
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
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

md_rand.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
md_rand.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
md_rand.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
md_rand.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
md_rand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
md_rand.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
md_rand.o: ../../include/openssl/symhacks.h rand_lcl.h
rand_egd.o: ../../include/openssl/opensslconf.h ../../include/openssl/rand.h
rand_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
rand_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rand_err.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
rand_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_err.o: ../../include/openssl/symhacks.h
rand_lib.o: ../../include/openssl/rand.h
rand_win.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
rand_win.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
rand_win.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_win.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
rand_win.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
rand_win.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
rand_win.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_win.o: ../cryptlib.h rand_lcl.h
randfile.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
randfile.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
randfile.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
randfile.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
randfile.o: ../../include/openssl/symhacks.h
