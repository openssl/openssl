#
# OpenSSL/crypto/md5/Makefile
#

DIR=    md5
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

MD5_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=md5_dgst.c md5_one.c
LIBOBJ=md5_dgst.o md5_one.o $(MD5_ASM_OBJ)

SRC= $(LIBSRC)

HEADER= md5_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

md5-586.s:	asm/md5-586.pl ../perlasm/x86asm.pl
	$(PERL) asm/md5-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

md5-x86_64.s:	asm/md5-x86_64.pl
	$(PERL) asm/md5-x86_64.pl $(PERLASM_SCHEME) > $@

md5-ia64.s: asm/md5-ia64.S
	$(CC) $(CFLAGS) -E asm/md5-ia64.S | \
	$(PERL) -ne 's/;\s+/;\n/g; print;' > $@

md5-sparcv9.S:	asm/md5-sparcv9.pl
	$(PERL) asm/md5-sparcv9.pl $@ $(CFLAGS)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

md5_dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/md5.h
md5_dgst.o: ../../include/openssl/opensslconf.h
md5_dgst.o: ../../include/openssl/opensslv.h ../include/internal/md32_common.h
md5_dgst.o: md5_dgst.c md5_locl.h
md5_one.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md5_one.o: ../../include/openssl/md5.h ../../include/openssl/opensslconf.h
md5_one.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
md5_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
md5_one.o: ../../include/openssl/symhacks.h md5_one.c
