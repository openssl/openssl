#
# OpenSSL/crypto/modes/Makefile
#

DIR=	modes
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

MODES_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= cbc128.c ctr128.c cts128.c cfb128.c ofb128.c gcm128.c
LIBOBJ= cbc128.o ctr128.o cts128.o cfb128.o ofb128.o gcm128.o \
	$(MODES_ASM_OBJ)

SRC= $(LIBSRC)

#EXHEADER= store.h str_compat.h
EXHEADER= modes.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

ghash-ia64.s:	asm/ghash-ia64.pl
	$(PERL) asm/ghash-ia64.pl $@ $(CFLAGS)
ghash-x86.s:	asm/ghash-x86.pl
	$(PERL) asm/ghash-x86.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
ghash-x86_64.s:	asm/ghash-x86_64.pl
	$(PERL) asm/ghash-x86_64.pl $(PERLASM_SCHEME) > $@
ghash-sparcv9.s:	asm/ghash-sparcv9.pl
	$(PERL) asm/ghash-sparcv9.pl $@ $(CFLAGS)
ghash-alpha.s:	asm/ghash-alpha.pl
	$(PERL) $< | $(CC) -E - | tee $@ > /dev/null
ghash-parisc.s:	asm/ghash-parisc.pl
	$(PERL) asm/ghash-parisc.pl $(PERLASM_SCHEME) $@

# GNU make "catch all"
ghash-%.s:	asm/ghash-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
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
	rm -f *.s *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cbc128.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cbc128.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
cbc128.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cbc128.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cbc128.o: ../../include/openssl/symhacks.h cbc128.c modes_lcl.h
cfb128.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cfb128.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
cfb128.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cfb128.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cfb128.o: ../../include/openssl/symhacks.h cfb128.c modes_lcl.h
ctr128.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ctr128.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
ctr128.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ctr128.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ctr128.o: ../../include/openssl/symhacks.h ctr128.c modes_lcl.h
cts128.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cts128.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
cts128.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cts128.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cts128.o: ../../include/openssl/symhacks.h cts128.c modes_lcl.h
gcm128.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
gcm128.o: ../../include/openssl/fips.h ../../include/openssl/modes.h
gcm128.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
gcm128.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
gcm128.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
gcm128.o: gcm128.c modes_lcl.h
ofb128.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ofb128.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
ofb128.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ofb128.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ofb128.o: ../../include/openssl/symhacks.h modes_lcl.h ofb128.c
