#
# OpenSSL/crypto/cast/Makefile
#

DIR=	cast
CPP=	$(CC) -E
INCLUDES=


CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=casttest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=c_skey.c c_ecb.c c_enc.c c_cfb64.c c_ofb64.c 
LIBOBJ=c_skey.o c_ecb.o $(CAST_ENC) c_cfb64.o c_ofb64.o

SRC= $(LIBSRC)

EXHEADER= cast.h
HEADER=	cast_s.h cast_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

cast-586.s:	asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL)	asm/cast-586.pl $(PERLASM_SCHEME) $(CLAGS) $(PROCESSOR) > $@

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

