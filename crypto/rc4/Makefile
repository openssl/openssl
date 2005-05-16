#
# SSLeay/crypto/rc4/Makefile
#

DIR=	rc4
TOP=	../..
CC=	cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
AR=		ar r

RC4_ENC=rc4_enc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=rc4test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=rc4_skey.c rc4_enc.c
LIBOBJ=rc4_skey.o $(RC4_ENC)

SRC= $(LIBSRC)

EXHEADER= rc4.h
HEADER=	$(EXHEADER) rc4_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

# ELF
rx86-elf.s: asm/rc4-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) rc4-586.pl elf $(CFLAGS) > ../$@)
# COFF
rx86-cof.s: asm/rc4-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) rc4-586.pl coff $(CFLAGS) > ../$@)
# a.out
rx86-out.s: asm/rc4-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) rc4-586.pl a.out $(CFLAGS) > ../$@)

rc4-x86_64.s: asm/rc4-x86_64.pl;	$(PERL) asm/rc4-x86_64.pl $@

rc4-ia64.s: asm/rc4-ia64.S
	$(CC) $(CFLAGS) -E asm/rc4-ia64.S > $@

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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

rc4_enc.o: rc4_enc.c rc4_locl.h
rc4_skey.o: rc4_locl.h rc4_skey.c
