#
# OpenSSL/crypto/bn/Makefile
#

DIR=	bn
CPP=    $(CC) -E
INCLUDES= -I.. -I$(TOP) -I../../include


CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=bntest.c exptest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	bn_add.c bn_div.c bn_exp.c bn_lib.c bn_ctx.c bn_mul.c bn_mod.c \
	bn_print.c bn_rand.c bn_shift.c bn_word.c bn_blind.c \
	bn_kron.c bn_sqrt.c bn_gcd.c bn_prime.c bn_err.c bn_sqr.c bn_asm.c \
	bn_recp.c bn_mont.c bn_mpi.c bn_exp2.c bn_gf2m.c bn_nist.c \
	bn_depr.c bn_const.c bn_x931p.c

LIBOBJ=	bn_add.o bn_div.o bn_exp.o bn_lib.o bn_ctx.o bn_mul.o bn_mod.o \
	bn_print.o bn_rand.o bn_shift.o bn_word.o bn_blind.o \
	bn_kron.o bn_sqrt.o bn_gcd.o bn_prime.o bn_err.o bn_sqr.o $(BN_ASM) \
	bn_recp.o bn_mont.o bn_mpi.o bn_exp2.o bn_gf2m.o bn_nist.o \
	bn_depr.o bn_const.o bn_x931p.o

SRC= $(LIBSRC)

EXHEADER= bn.h
HEADER=	bn_lcl.h bn_prime.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

bn_prime.h: bn_prime.pl
	$(PERL) bn_prime.pl >bn_prime.h

divtest: divtest.c ../../libcrypto.a
	cc -I../../include divtest.c -o divtest ../../libcrypto.a

bnbug: bnbug.c ../../libcrypto.a top
	cc -g -I../../include bnbug.c -o bnbug ../../libcrypto.a

lib:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

bn-586.s:	asm/bn-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/bn-586.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
co-586.s:	asm/co-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/co-586.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
x86-mont.s:	asm/x86-mont.pl ../perlasm/x86asm.pl
	$(PERL) asm/x86-mont.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
x86-gf2m.s:	asm/x86-gf2m.pl ../perlasm/x86asm.pl
	$(PERL) asm/x86-gf2m.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

sparcv8.o:	asm/sparcv8.S
	$(CC) $(CFLAGS) -c asm/sparcv8.S
bn-sparcv9.o:	asm/sparcv8plus.S
	$(CC) $(CFLAGS) -c -o $@ asm/sparcv8plus.S
sparcv9a-mont.s:	asm/sparcv9a-mont.pl
	$(PERL) asm/sparcv9a-mont.pl $(CFLAGS) > $@
sparcv9-mont.s:		asm/sparcv9-mont.pl
	$(PERL) asm/sparcv9-mont.pl $(CFLAGS) > $@
vis3-mont.s:		asm/vis3-mont.pl
	$(PERL) asm/vis3-mont.pl $(CFLAGS) > $@
sparct4-mont.S:	asm/sparct4-mont.pl
	$(PERL) asm/sparct4-mont.pl $(CFLAGS) > $@
sparcv9-gf2m.S:	asm/sparcv9-gf2m.pl
	$(PERL) asm/sparcv9-gf2m.pl $(CFLAGS) > $@

bn-mips3.o:	asm/mips3.s
	@if [ "$(CC)" = "gcc" ]; then \
		ABI=`expr "$(CFLAGS)" : ".*-mabi=\([n3264]*\)"` && \
		as -$$ABI -O -o $@ asm/mips3.s; \
	else	$(CC) -c $(CFLAGS) -o $@ asm/mips3.s; fi

bn-mips.s:	asm/mips.pl
	$(PERL) asm/mips.pl $(PERLASM_SCHEME) $@
mips-mont.s:	asm/mips-mont.pl
	$(PERL)	asm/mips-mont.pl $(PERLASM_SCHEME) $@

bn-s390x.o:	asm/s390x.S
	$(CC) $(CFLAGS) -c -o $@ asm/s390x.S
s390x-gf2m.s:	asm/s390x-gf2m.pl
	$(PERL) asm/s390x-gf2m.pl $(PERLASM_SCHEME) $@

x86_64-gcc.o:	asm/x86_64-gcc.c
	$(CC) $(CFLAGS) -c -o $@ asm/x86_64-gcc.c
x86_64-mont.s:	asm/x86_64-mont.pl
	$(PERL) asm/x86_64-mont.pl $(PERLASM_SCHEME) > $@
x86_64-mont5.s:	asm/x86_64-mont5.pl
	$(PERL) asm/x86_64-mont5.pl $(PERLASM_SCHEME) > $@
x86_64-gf2m.s:	asm/x86_64-gf2m.pl
	$(PERL) asm/x86_64-gf2m.pl $(PERLASM_SCHEME) > $@
modexp512-x86_64.s:	asm/modexp512-x86_64.pl
	$(PERL) asm/modexp512-x86_64.pl $(PERLASM_SCHEME) > $@
rsaz-x86_64.s:	asm/rsaz-x86_64.pl
	$(PERL) asm/rsaz-x86_64.pl $(PERLASM_SCHEME) > $@
rsaz-avx2.s:	asm/rsaz-avx2.pl 
	$(PERL) asm/rsaz-avx2.pl $(PERLASM_SCHEME) > $@

bn-ia64.s:	asm/ia64.S
	$(CC) $(CFLAGS) -E asm/ia64.S > $@
ia64-mont.s:	asm/ia64-mont.pl
	$(PERL) asm/ia64-mont.pl $@ $(CFLAGS)

# GNU assembler fails to compile PA-RISC2 modules, insist on calling
# vendor assembler...
pa-risc2W.o: asm/pa-risc2W.s
	$(PERL) $(TOP)/util/fipsas.pl $(TOP) $< /usr/ccs/bin/as -o pa-risc2W.o asm/pa-risc2W.s
pa-risc2.o: asm/pa-risc2.s
	$(PERL) $(TOP)/util/fipsas.pl $(TOP) $< /usr/ccs/bin/as -o pa-risc2.o asm/pa-risc2.s

parisc-mont.s:	asm/parisc-mont.pl
	$(PERL) asm/parisc-mont.pl $(PERLASM_SCHEME) $@

# ppc - AIX, Linux, MacOS X...
bn-ppc.s:	asm/ppc.pl;	$(PERL) asm/ppc.pl $(PERLASM_SCHEME) $@
ppc-mont.s:	asm/ppc-mont.pl;$(PERL) asm/ppc-mont.pl $(PERLASM_SCHEME) $@
ppc64-mont.s:	asm/ppc64-mont.pl;$(PERL) asm/ppc64-mont.pl $(PERLASM_SCHEME) $@

alpha-mont.s:	asm/alpha-mont.pl
	(preproc=/tmp/$$$$.$@; trap "rm $$preproc" INT; \
	$(PERL) asm/alpha-mont.pl > $$preproc && \
	$(CC) -E $$preproc > $@ && rm $$preproc)

# GNU make "catch all"
%-mont.S:	asm/%-mont.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
%-gf2m.S:	asm/%-gf2m.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

armv4-mont.o:	armv4-mont.S
armv4-gf2m.o:	armv4-gf2m.S

files:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

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

div:
	rm -f a.out
	gcc -I.. -g div.c ../../libcrypto.a

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

