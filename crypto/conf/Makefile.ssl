#
# SSLeay/crypto/conf/Makefile
#

DIR=	conf
TOP=	../..
CC=	cc
INCLUDES= -I.. -I../../include
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
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= conf_err.c conf_lib.c conf_api.c conf_def.c

LIBOBJ=	conf_err.o conf_lib.o conf_api.o conf_def.o

SRC= $(LIBSRC)

EXHEADER= conf.h conf_api.h
HEADER=	conf_def.h $(EXHEADER)

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
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

conf_api.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
conf_api.o: ../../include/openssl/conf_api.h ../../include/openssl/crypto.h
conf_api.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
conf_api.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
conf_api.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_api.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_def.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
conf_def.o: ../../include/openssl/conf.h ../../include/openssl/conf_api.h
conf_def.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
conf_def.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
conf_def.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
conf_def.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_def.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_def.o: conf_def.h
conf_err.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
conf_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
conf_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
conf_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
conf_err.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
conf_lib.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
conf_lib.o: ../../include/openssl/conf_api.h ../../include/openssl/crypto.h
conf_lib.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
conf_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
conf_lib.o: ../../include/openssl/opensslconf.h
conf_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
conf_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
