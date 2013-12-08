#
# crypto/seed/Makefile
#

DIR=	seed
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=seed.c seed_ecb.c seed_cbc.c seed_cfb.c seed_ofb.c
LIBOBJ=seed.o seed_ecb.o seed_cbc.o seed_cfb.o seed_ofb.o

SRC= $(LIBSRC)

EXHEADER= seed.h
HEADER= seed_locl.h $(EXHEADER)

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
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

seed.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed.o: ../../include/openssl/stack.h seed.c seed_locl.h
seed_cbc.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_cbc.o: ../../include/openssl/stack.h seed_cbc.c
seed_cfb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_cfb.o: ../../include/openssl/stack.h seed_cfb.c
seed_ecb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_ecb.o: ../../include/openssl/stack.h seed_ecb.c
seed_ofb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_ofb.o: ../../include/openssl/stack.h seed_ofb.c
