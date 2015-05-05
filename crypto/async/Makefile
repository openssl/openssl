#
# OpenSSL/crypto/async/Makefile
#

DIR=	async
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=async.c arch/async_posix.c arch/async_win.c
LIBOBJ=async.o arch/async_posix.o arch/async_win.o

SRC= $(LIBSRC)

EXHEADER= async.h
HEADER=	$(EXHEADER) async_locl.h arch/async_posix.h arch/async_win.h

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

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
	rm -f arch/*.o arch/*.obj arch/lib arch/tags arch/core arch/.pure arch/.nfs* arch/*.old arch/*.bak arch/fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

arch/async_posix.o: ../../e_os.h ../../include/openssl/async.h
arch/async_posix.o: ../../include/openssl/crypto.h
arch/async_posix.o: ../../include/openssl/e_os2.h
arch/async_posix.o: ../../include/openssl/opensslconf.h
arch/async_posix.o: ../../include/openssl/opensslv.h
arch/async_posix.o: ../../include/openssl/ossl_typ.h
arch/async_posix.o: ../../include/openssl/safestack.h
arch/async_posix.o: ../../include/openssl/stack.h
arch/async_posix.o: ../../include/openssl/symhacks.h arch/../arch/async_null.h
arch/async_posix.o: arch/../arch/async_posix.h arch/../arch/async_win.h
arch/async_posix.o: arch/../async_locl.h arch/async_posix.c
arch/async_win.o: ../../include/openssl/async.h arch/async_win.c
arch/async_win.o: arch/async_win.h
async.o: ../../e_os.h ../../include/openssl/async.h
async.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
async.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
async.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
async.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
async.o: arch/async_null.h arch/async_posix.h arch/async_win.h async.c
async.o: async_locl.h
