#
# OpenSSL/crypto/bn/Makefile
#

CPP_crypto_bn=    $(CC) -E


CFLAGS_crypto_bn= $(INCLUDES_crypto) $(CFLAG)
ASFLAGS_crypto_bn= $(INCLUDES_crypto) $(ASFLAG)
AFLAGS_crypto_bn= $(ASFLAGS_crypto_bn)

GENERAL_crypto_bn=crypto/bn/Makefile
TEST_crypto_bn=crypto/bn/bntest.c crypto/bn/exptest.c
APPS_crypto_bn=

LIB_crypto_bn=libcrypto.a
LIBSRC_crypto_bn=	crypto/bn/bn_add.c crypto/bn/bn_div.c crypto/bn/bn_exp.c crypto/bn/bn_lib.c crypto/bn/bn_ctx.c crypto/bn/bn_mul.c crypto/bn/bn_mod.c \
	crypto/bn/bn_print.c crypto/bn/bn_rand.c crypto/bn/bn_shift.c crypto/bn/bn_word.c crypto/bn/bn_blind.c \
	crypto/bn/bn_kron.c crypto/bn/bn_sqrt.c crypto/bn/bn_gcd.c crypto/bn/bn_prime.c crypto/bn/bn_err.c crypto/bn/bn_sqr.c crypto/bn/bn_asm.c \
	crypto/bn/bn_recp.c crypto/bn/bn_mont.c crypto/bn/bn_mpi.c crypto/bn/bn_exp2.c crypto/bn/bn_gf2m.c crypto/bn/bn_nist.c \
	crypto/bn/bn_depr.c crypto/bn/bn_const.c crypto/bn/bn_x931p.c

LIBOBJ_crypto_bn=	crypto/bn/bn_add.o crypto/bn/bn_div.o crypto/bn/bn_exp.o crypto/bn/bn_lib.o crypto/bn/bn_ctx.o crypto/bn/bn_mul.o crypto/bn/bn_mod.o \
	crypto/bn/bn_print.o crypto/bn/bn_rand.o crypto/bn/bn_shift.o crypto/bn/bn_word.o crypto/bn/bn_blind.o \
	crypto/bn/bn_kron.o crypto/bn/bn_sqrt.o crypto/bn/bn_gcd.o crypto/bn/bn_prime.o crypto/bn/bn_err.o crypto/bn/bn_sqr.o $(BN_ASM) \
	crypto/bn/bn_recp.o crypto/bn/bn_mont.o crypto/bn/bn_mpi.o crypto/bn/bn_exp2.o crypto/bn/bn_gf2m.o crypto/bn/bn_nist.o \
	crypto/bn/bn_depr.o crypto/bn/bn_const.o crypto/bn/bn_x931p.o

SRC_crypto_bn= $(LIBSRC_crypto_bn)

EXHEADER_crypto_bn= crypto/bn/bn.h
HEADER_crypto_bn=	crypto/bn/bn_lcl.h crypto/bn/bn_prime.h $(EXHEADER_crypto_bn)

ALL_crypto_bn=    $(GENERAL_crypto_bn) $(SRC_crypto_bn) $(HEADER_crypto_bn)


all: all_crypto_bn
all_crypto_bn:	crypto/bn/lib

crypto/bn/bn_prime.h: crypto/bn/bn_prime.pl
	$(PERL) crypto/bn/bn_prime.pl >crypto/bn/bn_prime.h

crypto/bn/divtest: crypto/bn/divtest.c ./libcrypto.a
	cc -Iinclude crypto/bn/divtest.c -o crypto/bn/divtest ./libcrypto.a

crypto/bn/bnbug: crypto/bn/bnbug.c ./libcrypto.a crypto/bn/top
	cc -g -Iinclude crypto/bn/bnbug.c -o crypto/bn/bnbug ./libcrypto.a

crypto/bn/lib:	$(LIBOBJ_crypto_bn)
	$(ARX) $(LIB_crypto_bn) $(LIBOBJ_crypto_bn)
	$(RANLIB) $(LIB_crypto_bn) || echo Never mind.
	@touch crypto/bn/lib

crypto/bn/bn-586.s:	crypto/bn/asm/bn-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/bn/asm/bn-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_bn) $(PROCESSOR) > $@
crypto/bn/co-586.s:	crypto/bn/asm/co-586.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/bn/asm/co-586.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_bn) $(PROCESSOR) > $@
crypto/bn/x86-mont.s:	crypto/bn/asm/x86-mont.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/bn/asm/x86-mont.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_bn) $(PROCESSOR) > $@
crypto/bn/x86-gf2m.s:	crypto/bn/asm/x86-gf2m.pl crypto/perlasm/x86asm.pl
	$(PERL) crypto/bn/asm/x86-gf2m.pl $(PERLASM_SCHEME) $(CFLAGS_crypto_bn) $(PROCESSOR) > $@

crypto/bn/sparcv8.o:	crypto/bn/asm/sparcv8.S
	$(CC) $(CFLAGS_crypto_bn) -c crypto/bn/asm/sparcv8.S
crypto/bn/bn-sparcv9.o:	crypto/bn/asm/sparcv8plus.S
	$(CC) $(CFLAGS_crypto_bn) -c -o $@ crypto/bn/asm/sparcv8plus.S
crypto/bn/sparcv9a-mont.s:	crypto/bn/asm/sparcv9a-mont.pl
	$(PERL) crypto/bn/asm/sparcv9a-mont.pl $(CFLAGS_crypto_bn) > $@
crypto/bn/sparcv9-mont.s:		crypto/bn/asm/sparcv9-mont.pl
	$(PERL) crypto/bn/asm/sparcv9-mont.pl $(CFLAGS_crypto_bn) > $@
crypto/bn/vis3-mont.s:		crypto/bn/asm/vis3-mont.pl
	$(PERL) crypto/bn/asm/vis3-mont.pl $(CFLAGS_crypto_bn) > $@
crypto/bn/sparct4-mont.S:	crypto/bn/asm/sparct4-mont.pl
	$(PERL) crypto/bn/asm/sparct4-mont.pl $(CFLAGS_crypto_bn) > $@
crypto/bn/sparcv9-gf2m.S:	crypto/bn/asm/sparcv9-gf2m.pl
	$(PERL) crypto/bn/asm/sparcv9-gf2m.pl $(CFLAGS_crypto_bn) > $@

crypto/bn/bn-mips3.o:	crypto/bn/asm/mips3.s
	@if [ "$(CC)" = "gcc" ]; then \
		ABI=`expr "$(CFLAGS_crypto_bn)" : ".*-mabi=\([n3264]*\)"` && \
		as -$$ABI -O -o $@ crypto/bn/asm/mips3.s; \
	else	$(CC) -c $(CFLAGS_crypto_bn) -o $@ crypto/bn/asm/mips3.s; fi

crypto/bn/bn-mips.s:	crypto/bn/asm/mips.pl
	$(PERL) crypto/bn/asm/mips.pl $(PERLASM_SCHEME) $@
crypto/bn/mips-mont.s:	crypto/bn/asm/mips-mont.pl
	$(PERL)	crypto/bn/asm/mips-mont.pl $(PERLASM_SCHEME) $@

crypto/bn/bn-s390x.o:	crypto/bn/asm/s390x.S
	$(CC) $(CFLAGS_crypto_bn) -c -o $@ crypto/bn/asm/s390x.S
crypto/bn/s390x-gf2m.s:	crypto/bn/asm/s390x-gf2m.pl
	$(PERL) crypto/bn/asm/s390x-gf2m.pl $(PERLASM_SCHEME) $@

crypto/bn/x86_64-gcc.o:	crypto/bn/asm/x86_64-gcc.c
	$(CC) $(CFLAGS_crypto_bn) -c -o $@ crypto/bn/asm/x86_64-gcc.c
crypto/bn/x86_64-mont.s:	crypto/bn/asm/x86_64-mont.pl
	$(PERL) crypto/bn/asm/x86_64-mont.pl $(PERLASM_SCHEME) > $@
crypto/bn/x86_64-mont5.s:	crypto/bn/asm/x86_64-mont5.pl
	$(PERL) crypto/bn/asm/x86_64-mont5.pl $(PERLASM_SCHEME) > $@
crypto/bn/x86_64-gf2m.s:	crypto/bn/asm/x86_64-gf2m.pl
	$(PERL) crypto/bn/asm/x86_64-gf2m.pl $(PERLASM_SCHEME) > $@
crypto/bn/modexp512-x86_64.s:	crypto/bn/asm/modexp512-x86_64.pl
	$(PERL) crypto/bn/asm/modexp512-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/bn/rsaz-x86_64.s:	crypto/bn/asm/rsaz-x86_64.pl
	$(PERL) crypto/bn/asm/rsaz-x86_64.pl $(PERLASM_SCHEME) > $@
crypto/bn/rsaz-avx2.s:	crypto/bn/asm/rsaz-avx2.pl 
	$(PERL) crypto/bn/asm/rsaz-avx2.pl $(PERLASM_SCHEME) > $@

crypto/bn/bn-ia64.s:	crypto/bn/asm/ia64.S
	$(CC) $(CFLAGS_crypto_bn) -E crypto/bn/asm/ia64.S > $@
crypto/bn/ia64-mont.s:	crypto/bn/asm/ia64-mont.pl
	$(PERL) crypto/bn/asm/ia64-mont.pl $@ $(CFLAGS_crypto_bn)

# GNU assembler fails to compile PA-RISC2 modules, insist on calling
# vendor assembler...
crypto/bn/pa-risc2W.o: crypto/bn/asm/pa-risc2W.s
	FIPSCANISTERINTERNAL="$(FIPSCANISTERINTERNAL)" $(PERL) util/fipsas.pl ./ $< /usr/ccs/bin/as -o crypto/bn/pa-risc2W.o crypto/bn/asm/pa-risc2W.s
crypto/bn/pa-risc2.o: crypto/bn/asm/pa-risc2.s
	FIPSCANISTERINTERNAL="$(FIPSCANISTERINTERNAL)" $(PERL) util/fipsas.pl ./ $< /usr/ccs/bin/as -o crypto/bn/pa-risc2.o crypto/bn/asm/pa-risc2.s

crypto/bn/parisc-mont.s:	crypto/bn/asm/parisc-mont.pl
	$(PERL) crypto/bn/asm/parisc-mont.pl $(PERLASM_SCHEME) $@

# ppc - AIX, Linux, MacOS X...
crypto/bn/bn-ppc.s:	crypto/bn/asm/ppc.pl;	$(PERL) crypto/bn/asm/ppc.pl $(PERLASM_SCHEME) $@
crypto/bn/ppc-mont.s:	crypto/bn/asm/ppc-mont.pl;$(PERL) crypto/bn/asm/ppc-mont.pl $(PERLASM_SCHEME) $@
crypto/bn/ppc64-mont.s:	crypto/bn/asm/ppc64-mont.pl;$(PERL) crypto/bn/asm/ppc64-mont.pl $(PERLASM_SCHEME) $@

crypto/bn/alpha-mont.s:	crypto/bn/asm/alpha-mont.pl
	(preproc=/tmp/$$$$.$@; trap "rm $$preproc" INT; \
	$(PERL) crypto/bn/asm/alpha-mont.pl > $$preproc && \
	$(CC) -E $$preproc > $@ && rm $$preproc)

# GNU make "catch all"
crypto/bn/%-mont.S:	crypto/bn/asm/%-mont.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
crypto/bn/%-gf2m.S:	crypto/bn/asm/%-gf2m.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

crypto/bn/armv4-mont.o:	crypto/bn/armv4-mont.S
crypto/bn/armv4-gf2m.o:	crypto/bn/armv4-gf2m.S

files: files_crypto_bn
files_crypto_bn:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_bn
links_crypto_bn:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_bn)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_bn)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_bn)

install: install_crypto_bn
install_crypto_bn:
	@[ -n "$(INSTALLTOP)" ] # should be set by crypto/bn/top Makefile...
	@headerlist="$(EXHEADER_crypto_bn)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

crypto/bn/div:
	rm -f a.out
	gcc -Icrypto -g crypto/bn/div.c ./libcrypto.a

tags: tags_crypto_bn
tags_crypto_bn:
	ctags $(SRC_crypto_bn)

tests: tests_crypto_bn
tests_crypto_bn:

lint: lint_crypto_bn
lint_crypto_bn:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_bn)>crypto/bn/fluff

dclean: dclean_crypto_bn
dclean_crypto_bn:

clean: clean_crypto_bn
clean_crypto_bn:
	rm -f crypto/bn/*.s crypto/bn/*.o crypto/bn/*.d crypto/bn/*.obj crypto/bn/lib crypto/bn/tags crypto/bn/core crypto/bn/.pure crypto/bn/.nfs* crypto/bn/*.old crypto/bn/*.bak crypto/bn/fluff

