#
# SSLeay/crypto/dh/Makefile
#

DIR=	dh
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
TEST= dhtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= dh_asn1.c dh_gen.c dh_key.c dh_lib.c dh_check.c dh_err.c
LIBOBJ= dh_asn1.o dh_gen.o dh_key.o dh_lib.o dh_check.o dh_err.o

SRC= $(LIBSRC)

EXHEADER= dh.h
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
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

dh_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
dh_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dh_asn1.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dh_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
dh_asn1.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
dh_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_asn1.o: ../../include/openssl/symhacks.h ../cryptlib.h dh_asn1.c
dh_check.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_check.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_check.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_check.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_check.o: ../../include/openssl/opensslconf.h
dh_check.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_check.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_check.o: ../../include/openssl/symhacks.h ../cryptlib.h dh_check.c
dh_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_err.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dh_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dh_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_err.o: ../../include/openssl/symhacks.h dh_err.c
dh_gen.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_gen.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_gen.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_gen.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_gen.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dh_gen.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
dh_gen.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dh_gen.o: ../cryptlib.h dh_gen.c
dh_key.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
dh_key.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dh_key.o: ../../include/openssl/dh.h ../../include/openssl/e_os2.h
dh_key.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
dh_key.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
dh_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
dh_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_key.o: ../../include/openssl/symhacks.h ../cryptlib.h dh_key.c
dh_lib.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
dh_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
dh_lib.o: ../../include/openssl/crypto.h ../../include/openssl/dh.h
dh_lib.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
dh_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dh_lib.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
dh_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
dh_lib.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
dh_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
dh_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
dh_lib.o: ../cryptlib.h dh_lib.c
