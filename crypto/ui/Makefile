#
# OpenSSL/crypto/ui/Makefile
#

DIR=	ui
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
#TEST= uitest.c
TEST=
APPS=

COMPATSRC= ui_compat.c
COMPATOBJ= ui_compat.o

LIB=$(TOP)/libcrypto.a
LIBSRC= ui_err.c ui_lib.c ui_openssl.c ui_util.c $(COMPATSRC)
LIBOBJ= ui_err.o ui_lib.o ui_openssl.o ui_util.o $(COMPATOBJ)

SRC= $(LIBSRC)

EXHEADER= ui.h ui_compat.h
HEADER=	$(EXHEADER) ui_locl.h

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
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
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
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ui_compat.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ui_compat.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
ui_compat.o: ui_compat.c
ui_err.o: ../../include/openssl/bio.h ../../include/openssl/err.h
ui_err.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
ui_err.o: ../../include/openssl/stack.h ../../include/openssl/ui.h ui_err.c
ui_lib.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
ui_lib.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
ui_lib.o: ../../include/openssl/stack.h ../../include/openssl/ui.h
ui_lib.o: ../cryptlib.h ui_lib.c ui_locl.h
ui_openssl.o: ../../e_os.h ../../include/openssl/bio.h
ui_openssl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ui_openssl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ui_openssl.o: ../../include/openssl/ui.h ../cryptlib.h ui_locl.h ui_openssl.c
ui_util.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ui_util.o: ../../include/openssl/ui.h ui_locl.h ui_util.c
