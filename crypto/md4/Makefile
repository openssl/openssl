#
# OpenSSL/crypto/md4/Makefile
#

DIR=    md4
CPP=    $(CC) -E
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=md4test.c
APPS=md4.c

LIB=$(TOP)/libcrypto.a
LIBSRC=md4_dgst.c md4_one.c
LIBOBJ=md4_dgst.o md4_one.o

SRC= $(LIBSRC)

EXHEADER= md4.h
HEADER= md4_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

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
	rm -f ../../include/openssl/$(EXHEADER) ../../test/$(TEST) ../../apps/$(APPS)

clean:
	rm -f asm/mx86unix.cpp *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

