#
# SSLeay/crypto/idea/Makefile
#

DIR=	idea
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
TEST=ideatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=i_cbc.c i_cfb64.c i_ofb64.c i_ecb.c i_skey.c
LIBOBJ=i_cbc.o i_cfb64.o i_ofb64.o i_ecb.o i_skey.o

SRC= $(LIBSRC)

EXHEADER= idea.h
HEADER=	idea_lcl.h $(EXHEADER)

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

i_cbc.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_cbc.o: idea_lcl.h
i_cfb64.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_cfb64.o: idea_lcl.h
i_ecb.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_ecb.o: ../../include/openssl/opensslv.h idea_lcl.h
i_ofb64.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_ofb64.o: idea_lcl.h
i_skey.o: ../../include/openssl/idea.h ../../include/openssl/opensslconf.h
i_skey.o: idea_lcl.h
