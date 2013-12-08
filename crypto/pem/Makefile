#
# OpenSSL/crypto/pem/Makefile
#

DIR=	pem
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= pem_sign.c pem_seal.c pem_info.c pem_lib.c pem_all.c pem_err.c \
	pem_x509.c pem_xaux.c pem_oth.c pem_pk8.c pem_pkey.c pvkfmt.c

LIBOBJ=	pem_sign.o pem_seal.o pem_info.o pem_lib.o pem_all.o pem_err.o \
	pem_x509.o pem_xaux.o pem_oth.o pem_pk8.o pem_pkey.o pvkfmt.o

SRC= $(LIBSRC)

EXHEADER= pem.h pem2.h
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

links: $(EXHEADER)
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

pem_all.o: ../../e_os.h ../../include/openssl/asn1.h
pem_all.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_all.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_all.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_all.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_all.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pem_all.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pem_all.o: ../cryptlib.h pem_all.c
pem_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pem_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pem_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pem_err.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
pem_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pem_err.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pem_err.o: ../../include/openssl/x509_vfy.h pem_err.c
pem_info.o: ../../e_os.h ../../include/openssl/asn1.h
pem_info.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_info.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_info.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_info.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_info.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pem_info.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pem_info.o: ../cryptlib.h pem_info.c
pem_lib.o: ../../e_os.h ../../include/openssl/asn1.h
pem_lib.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
pem_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pem_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pem_lib.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
pem_lib.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
pem_lib.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
pem_lib.o: ../../include/openssl/stack.h ../../include/openssl/ui.h
pem_lib.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
pem_lib.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
pem_lib.o: pem_lib.c
pem_oth.o: ../../e_os.h ../../include/openssl/asn1.h
pem_oth.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_oth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_oth.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_oth.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_oth.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
pem_oth.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pem_oth.o: ../../include/openssl/x509_vfy.h ../cryptlib.h pem_oth.c
pem_pk8.o: ../../e_os.h ../../include/openssl/asn1.h
pem_pk8.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_pk8.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_pk8.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_pk8.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs12.h
pem_pk8.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
pem_pk8.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pem_pk8.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pem_pk8.o: ../cryptlib.h pem_pk8.c
pem_pkey.o: ../../e_os.h ../../include/openssl/asn1.h
pem_pkey.o: ../../include/openssl/bio.h ../../include/openssl/engine.h
pem_pkey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pem_pkey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pem_pkey.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
pem_pkey.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
pem_pkey.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
pem_pkey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pem_pkey.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
pem_pkey.o: pem_pkey.c
pem_seal.o: ../../e_os.h ../../include/openssl/asn1.h
pem_seal.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_seal.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_seal.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_seal.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_seal.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
pem_seal.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pem_seal.o: ../../include/openssl/x509_vfy.h ../cryptlib.h pem_seal.c
pem_sign.o: ../../e_os.h ../../include/openssl/asn1.h
pem_sign.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_sign.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_sign.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_sign.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_sign.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
pem_sign.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pem_sign.o: ../../include/openssl/x509_vfy.h ../cryptlib.h pem_sign.c
pem_x509.o: ../../e_os.h ../../include/openssl/asn1.h
pem_x509.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_x509.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_x509.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_x509.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_x509.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pem_x509.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pem_x509.o: ../cryptlib.h pem_x509.c
pem_xaux.o: ../../e_os.h ../../include/openssl/asn1.h
pem_xaux.o: ../../include/openssl/bio.h ../../include/openssl/err.h
pem_xaux.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pem_xaux.o: ../../include/openssl/objects.h ../../include/openssl/pem.h
pem_xaux.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
pem_xaux.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pem_xaux.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pem_xaux.o: ../cryptlib.h pem_xaux.c
pvkfmt.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
pvkfmt.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pvkfmt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pvkfmt.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
pvkfmt.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
pvkfmt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pvkfmt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pvkfmt.o: ../cryptlib.h pvkfmt.c
