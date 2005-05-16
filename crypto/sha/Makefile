#
# SSLeay/crypto/sha/Makefile
#

DIR=    sha
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=       Makefile
AR=             ar r

SHA1_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=shatest.c sha1test.c sha256t.c sha512t.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=sha_dgst.c sha1dgst.c sha_one.c sha1_one.c sha256.c sha512.c
LIBOBJ=sha_dgst.o sha1dgst.o sha_one.o sha1_one.o sha256.o sha512.o $(SHA1_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= sha.h
HEADER= sha_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

# ELF
sx86-elf.s: asm/sha1-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) sha1-586.pl elf $(CFLAGS) $(PROCESSOR) > ../$@)
s512sse2-elf.s:	asm/sha512-sse2.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) sha512-sse2.pl elf $(CFLAGS) $(PROCESSOR) > ../$@)
# COFF
sx86-cof.s: asm/sha1-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) sha1-586.pl coff $(CFLAGS) $(PROCESSOR) > ../$@)
s512sse2-cof.s:     asm/sha512-sse2.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) sha512-sse2.pl coff $(CFLAGS) $(PROCESSOR) > ../$@)
# a.out
sx86-out.s: asm/sha1-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) sha1-586.pl a.out $(CFLAGS) $(PROCESSOR) > ../$@)
s512sse2-out.s:     asm/sha512-sse2.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) sha512-sse2.pl a.out $(CFLAGS) $(PROCESSOR) > ../$@)

sha1-ia64.s:   asm/sha1-ia64.pl
	(cd asm; $(PERL) sha1-ia64.pl $(CFLAGS) ) > $@
sha256-ia64.s: asm/sha512-ia64.pl
	(cd asm; $(PERL) sha512-ia64.pl ../$@ $(CFLAGS))
sha512-ia64.s: asm/sha512-ia64.pl
	(cd asm; $(PERL) sha512-ia64.pl ../$@ $(CFLAGS))

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

sha1_one.o: sha1_one.c
sha512.o: sha512.c
sha_one.o: sha_one.c
