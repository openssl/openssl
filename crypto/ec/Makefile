#
# crypto/ec/Makefile
#

DIR=	ec
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=ectest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	ec_lib.c ecp_smpl.c ecp_mont.c ecp_recp.c ecp_nist.c ec_cvt.c ec_mult.c \
	ec_err.c

LIBOBJ=	ec_lib.o ecp_smpl.o ecp_mont.o ecp_recp.o ecp_nist.o ec_cvt.o ec_mult.o \
	ec_err.o

SRC= $(LIBSRC)

EXHEADER= ec.h
HEADER=	ec_lcl.h $(EXHEADER)

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

ec_cvt.o: ../../include/openssl/bn.h ../../include/openssl/e_os2.h
ec_cvt.o: ../../include/openssl/ec.h ../../include/openssl/opensslconf.h
ec_cvt.o: ../../include/openssl/symhacks.h ec_cvt.c ec_lcl.h
ec_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ec_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ec_err.o: ../../include/openssl/ec.h ../../include/openssl/err.h
ec_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ec_err.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ec_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ec_err.o: ec_err.c
ec_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ec_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ec_lib.o: ../../include/openssl/ec.h ../../include/openssl/err.h
ec_lib.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ec_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ec_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ec_lib.o: ec_lcl.h ec_lib.c
ec_mult.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ec_mult.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ec_mult.o: ../../include/openssl/ec.h ../../include/openssl/err.h
ec_mult.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ec_mult.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ec_mult.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ec_mult.o: ec_lcl.h ec_mult.c
ecp_mont.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ecp_mont.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ecp_mont.o: ../../include/openssl/ec.h ../../include/openssl/err.h
ecp_mont.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ecp_mont.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ecp_mont.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecp_mont.o: ec_lcl.h ecp_mont.c
ecp_nist.o: ../../include/openssl/bn.h ../../include/openssl/e_os2.h
ecp_nist.o: ../../include/openssl/ec.h ../../include/openssl/opensslconf.h
ecp_nist.o: ../../include/openssl/symhacks.h ec_lcl.h ecp_nist.c
ecp_recp.o: ../../include/openssl/bn.h ../../include/openssl/e_os2.h
ecp_recp.o: ../../include/openssl/ec.h ../../include/openssl/opensslconf.h
ecp_recp.o: ../../include/openssl/symhacks.h ec_lcl.h ecp_recp.c
ecp_smpl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ecp_smpl.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ecp_smpl.o: ../../include/openssl/ec.h ../../include/openssl/err.h
ecp_smpl.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ecp_smpl.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ecp_smpl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecp_smpl.o: ec_lcl.h ecp_smpl.c
