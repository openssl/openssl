#
# SSLeay/crypto/comp/Makefile
#

DIR=	comp
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
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
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= comp_lib.c comp_err.c \
	c_rle.c c_zlib.c

LIBOBJ=	comp_lib.o comp_err.o \
	c_rle.o c_zlib.o

SRC= $(LIBSRC)

EXHEADER= comp.h
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

c_rle.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
c_rle.o: ../../include/openssl/bn.h ../../include/openssl/comp.h
c_rle.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
c_rle.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
c_rle.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
c_rle.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
c_rle.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h c_rle.c
c_zlib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
c_zlib.o: ../../include/openssl/bn.h ../../include/openssl/comp.h
c_zlib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
c_zlib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
c_zlib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
c_zlib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
c_zlib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
c_zlib.o: c_zlib.c
comp_err.o: ../../include/openssl/bio.h ../../include/openssl/comp.h
comp_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
comp_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
comp_err.o: ../../include/openssl/opensslconf.h
comp_err.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
comp_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
comp_err.o: comp_err.c
comp_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
comp_lib.o: ../../include/openssl/bn.h ../../include/openssl/comp.h
comp_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
comp_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
comp_lib.o: ../../include/openssl/opensslconf.h
comp_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
comp_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
comp_lib.o: ../../include/openssl/symhacks.h comp_lib.c
