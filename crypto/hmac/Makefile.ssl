#
# SSLeay/crypto/md/Makefile
#

DIR=	hmac
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
TEST=hmactest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=hmac.c
LIBOBJ=hmac.o

SRC= $(LIBSRC)

EXHEADER= hmac.h
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

hmac.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
hmac.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
hmac.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
hmac.o: ../../include/openssl/des.h ../../include/openssl/dh.h
hmac.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
hmac.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
hmac.o: ../../include/openssl/idea.h ../../include/openssl/md2.h
hmac.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
hmac.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
hmac.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
hmac.o: ../../include/openssl/opensslv.h ../../include/openssl/rc2.h
hmac.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
hmac.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
hmac.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
hmac.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
