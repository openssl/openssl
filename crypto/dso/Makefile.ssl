#
# SSLeay/crypto/dso/Makefile
#

DIR=	dso
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
LIBSRC= dso_dl.c dso_dlfcn.c dso_err.c dso_lib.c dso_null.c \
	dso_openssl.c dso_win32.c dso_vms.c
LIBOBJ= dso_dl.o dso_dlfcn.o dso_err.o dso_lib.o dso_null.o \
	dso_openssl.o dso_win32.o dso_vms.o

SRC= $(LIBSRC)

EXHEADER= dso.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
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
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

dso_dl.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_dl.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_dl.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_dl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_dl.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_dl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_dl.o: ../../include/openssl/symhacks.h ../cryptlib.h
dso_dlfcn.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_dlfcn.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_dlfcn.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_dlfcn.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_dlfcn.o: ../../include/openssl/opensslconf.h
dso_dlfcn.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
dso_dlfcn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_dlfcn.o: ../cryptlib.h
dso_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
dso_err.o: ../../include/openssl/dso.h ../../include/openssl/err.h
dso_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslv.h
dso_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_err.o: ../../include/openssl/symhacks.h
dso_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_lib.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_lib.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_lib.o: ../../include/openssl/symhacks.h ../cryptlib.h
dso_null.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_null.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_null.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_null.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_null.o: ../../include/openssl/opensslconf.h
dso_null.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
dso_null.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_null.o: ../cryptlib.h
dso_openssl.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_openssl.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_openssl.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_openssl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_openssl.o: ../../include/openssl/opensslconf.h
dso_openssl.o: ../../include/openssl/opensslv.h
dso_openssl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_openssl.o: ../../include/openssl/symhacks.h ../cryptlib.h
dso_vms.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_vms.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_vms.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_vms.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_vms.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dso_vms.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dso_vms.o: ../../include/openssl/symhacks.h ../cryptlib.h
dso_win32.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
dso_win32.o: ../../include/openssl/crypto.h ../../include/openssl/dso.h
dso_win32.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
dso_win32.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dso_win32.o: ../../include/openssl/opensslconf.h
dso_win32.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
dso_win32.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dso_win32.o: ../cryptlib.h
