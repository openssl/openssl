#
# OpenSSL/crypto/kdf/Makefile
#

DIR=	kdf
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= kdf_snmp.c kdf_err.c kdf_srtp.c kdf_ssh.c kdf_802_11i.c kdf_tls.c kdf_ikev2.c
LIBOBJ= kdf_snmp.o kdf_err.o kdf_srtp.o kdf_ssh.o kdf_802_11i.o kdf_tls.o kdf_ikev2.o

SRC= $(LIBSRC)

EXHEADER= kdf.h
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

# We need to use force because 'install' matches 'INSTALL' on case
# insensitive systems
FRC.install:
install: FRC.install
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
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

kdf_snmp.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
kdf_snmp.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_snmp.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
kdf_snmp.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
kdf_snmp.o: ../../include/openssl/opensslconf.h
kdf_snmp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kdf_snmp.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
kdf_snmp.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_snmp.o: ../crypto.h kdf_snmp.c
