#
# OpenSSL/crypto/rand/Makefile
#

DIR=	rand
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= randtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md_rand.c randfile.c rand_lib.c rand_err.c rand_egd.c \
	rand_win.c rand_unix.c rand_os2.c rand_nw.c
LIBOBJ=md_rand.o randfile.o rand_lib.o rand_err.o rand_egd.o \
	rand_win.o rand_unix.o rand_os2.o rand_nw.o

SRC= $(LIBSRC)

EXHEADER= rand.h
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

md_rand.o: ../../e_os.h ../../include/openssl/asn1.h
md_rand.o: ../../include/openssl/bio.h ../../include/openssl/err.h
md_rand.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
md_rand.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
md_rand.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
md_rand.o: md_rand.c rand_lcl.h
rand_egd.o: ../../include/openssl/rand.h rand_egd.c
rand_err.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rand_err.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
rand_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_err.o: rand_err.c
rand_lib.o: ../../e_os.h ../../include/openssl/asn1.h
rand_lib.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
rand_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rand_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
rand_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
rand_lib.o: ../cryptlib.h rand_lib.c
rand_nw.o: ../../e_os.h ../../include/openssl/asn1.h
rand_nw.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rand_nw.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rand_nw.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rand_nw.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_nw.o: ../cryptlib.h rand_lcl.h rand_nw.c
rand_os2.o: ../../e_os.h ../../include/openssl/asn1.h
rand_os2.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rand_os2.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rand_os2.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rand_os2.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_os2.o: ../cryptlib.h rand_lcl.h rand_os2.c
rand_unix.o: ../../e_os.h ../../include/openssl/asn1.h
rand_unix.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rand_unix.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rand_unix.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rand_unix.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_unix.o: ../cryptlib.h rand_lcl.h rand_unix.c
rand_win.o: ../../e_os.h ../../include/openssl/asn1.h
rand_win.o: ../../include/openssl/bio.h ../../include/openssl/err.h
rand_win.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
rand_win.o: ../../include/openssl/objects.h ../../include/openssl/rand.h
rand_win.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rand_win.o: ../cryptlib.h rand_lcl.h rand_win.c
randfile.o: ../../e_os.h ../../include/openssl/rand.h
randfile.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
randfile.o: randfile.c
