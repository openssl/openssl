#
# SSLeay/crypto/bn/Makefile
#

DIR=	bn
TOP=	../..
CC=	cc
CPP=    $(CC) -E
INCLUDES= -I.. -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
AR=		ar r

BN_ASM=		bn_asm.o
# or use
#BN_ASM=	bn86-elf.o

CFLAGS= $(INCLUDES) $(CFLAG)

# We let the C compiler driver to take care of .s files. This is done in
# order to be excused from maintaining a separate set of architecture
# dependent assembler flags. E.g. if you throw -mcpu=ultrasparc at SPARC
# gcc, then the driver will automatically translate it to -xarch=v8plus
# and pass it down to assembler.
AS=$(CC) -c
ASFLAGS=$(CFLAGS)

GENERAL=Makefile
TEST=bntest.c exptest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	bn_add.c bn_div.c bn_exp.c bn_lib.c bn_ctx.c bn_mul.c \
	bn_print.c bn_rand.c bn_shift.c bn_word.c bn_blind.c \
	bn_gcd.c bn_prime.c bn_err.c bn_sqr.c bn_asm.c bn_recp.c bn_mont.c \
	bn_mpi.c bn_exp2.c

LIBOBJ=	bn_add.o bn_div.o bn_exp.o bn_lib.o bn_ctx.o bn_mul.o \
	bn_print.o bn_rand.o bn_shift.o bn_word.o bn_blind.o \
	bn_gcd.o bn_prime.o bn_err.o bn_sqr.o $(BN_ASM) bn_recp.o bn_mont.o \
	bn_mpi.o bn_exp2.o

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
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB)
	@touch lib

# elf
asm/bn86-elf.o: asm/bn86unix.cpp
	$(CPP) -DELF -x c asm/bn86unix.cpp | as -o asm/bn86-elf.o

asm/co86-elf.o: asm/co86unix.cpp
	$(CPP) -DELF -x c asm/co86unix.cpp | as -o asm/co86-elf.o

# solaris
asm/bn86-sol.o: asm/bn86unix.cpp
	$(CC) -E -DSOL asm/bn86unix.cpp | sed 's/^#.*//' > asm/bn86-sol.s
	as -o asm/bn86-sol.o asm/bn86-sol.s
	rm -f asm/bn86-sol.s

asm/co86-sol.o: asm/co86unix.cpp
	$(CC) -E -DSOL asm/co86unix.cpp | sed 's/^#.*//' > asm/co86-sol.s
	as -o asm/co86-sol.o asm/co86-sol.s
	rm -f asm/co86-sol.s

# a.out
asm/bn86-out.o: asm/bn86unix.cpp
	$(CPP) -DOUT asm/bn86unix.cpp | as -o asm/bn86-out.o

asm/co86-out.o: asm/co86unix.cpp
	$(CPP) -DOUT asm/co86unix.cpp | as -o asm/co86-out.o

# bsdi
asm/bn86bsdi.o: asm/bn86unix.cpp
	$(CPP) -DBSDI asm/bn86unix.cpp | sed 's/ :/:/' | as -o asm/bn86bsdi.o

asm/co86bsdi.o: asm/co86unix.cpp
	$(CPP) -DBSDI asm/co86unix.cpp | sed 's/ :/:/' | as -o asm/co86bsdi.o

asm/bn86unix.cpp: asm/bn-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) bn-586.pl cpp >bn86unix.cpp )

asm/co86unix.cpp: asm/co-586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) co-586.pl cpp >co86unix.cpp )

asm/sparcv8.o: asm/sparcv8.S

asm/sparcv8plus.o: asm/sparcv8plus.S

# Old GNU assembler doesn't understand V9 instructions, so we
# hire /usr/ccs/bin/as to do the job. Note that option is called
# *-gcc27, but even gcc 2>=8 users may experience similar problem
# if they didn't bother to upgrade GNU assembler. Such users should
# not choose this option, but be adviced to *remove* GNU assembler
# or upgrade it.
asm/sparcv8plus-gcc27.o: asm/sparcv8plus.S
	$(CC) $(ASFLAGS) -E asm/sparcv8plus.S | \
		/usr/ccs/bin/as -xarch=v8plus - -o asm/sparcv8plus-gcc27.o

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

exptest:
	rm -f exptest
	gcc -I../../include -g2 -ggdb -o exptest exptest.c ../../libcrypto.a

div:
	rm -f a.out
	gcc -I.. -g div.c ../../libcrypto.a

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f asm/co86unix.cpp asm/bn86unix.cpp *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff bn_asm.s

# DO NOT DELETE THIS LINE -- make depend depends on it.

bn_add.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_add.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_add.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_add.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_add.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_add.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_add.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_asm.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_asm.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_asm.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_asm.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_asm.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_asm.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_asm.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_blind.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_blind.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_blind.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_blind.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_blind.o: ../../include/openssl/opensslconf.h
bn_blind.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bn_blind.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bn_blind.o: ../cryptlib.h bn_lcl.h
bn_ctx.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_ctx.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_ctx.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_ctx.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_ctx.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_ctx.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_ctx.o: ../../include/openssl/symhacks.h ../cryptlib.h
bn_div.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_div.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_div.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_div.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_div.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_div.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_div.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_err.o: ../../include/openssl/crypto.h ../../include/openssl/err.h
bn_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bn_err.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bn_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bn_exp.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_exp.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_exp.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_exp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_exp.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_exp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_exp.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_exp2.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_exp2.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_exp2.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_exp2.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_exp2.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_exp2.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_exp2.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_gcd.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_gcd.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_gcd.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_gcd.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_gcd.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_gcd.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_gcd.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_lib.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_lib.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_mont.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_mont.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_mont.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_mont.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_mont.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_mont.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_mont.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_mpi.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_mpi.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_mpi.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_mpi.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_mpi.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_mpi.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_mpi.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_mul.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_mul.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_mul.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_mul.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_mul.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_mul.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_mul.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_prime.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_prime.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_prime.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_prime.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_prime.o: ../../include/openssl/opensslconf.h
bn_prime.o: ../../include/openssl/opensslv.h ../../include/openssl/rand.h
bn_prime.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_prime.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h bn_prime.h
bn_print.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_print.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_print.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_print.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_print.o: ../../include/openssl/opensslconf.h
bn_print.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bn_print.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bn_print.o: ../cryptlib.h bn_lcl.h
bn_rand.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_rand.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_rand.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_rand.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_rand.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_rand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
bn_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bn_rand.o: ../cryptlib.h bn_lcl.h
bn_recp.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_recp.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_recp.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_recp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_recp.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_recp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_recp.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_shift.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_shift.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_shift.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_shift.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_shift.o: ../../include/openssl/opensslconf.h
bn_shift.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bn_shift.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bn_shift.o: ../cryptlib.h bn_lcl.h
bn_sqr.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_sqr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_sqr.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_sqr.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_sqr.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_sqr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_sqr.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
bn_word.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
bn_word.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
bn_word.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bn_word.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bn_word.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bn_word.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bn_word.o: ../../include/openssl/symhacks.h ../cryptlib.h bn_lcl.h
