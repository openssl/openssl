#
# OpenSSL/crypto/conf/Makefile
#

DIR=	conf
INCLUDES= -I.. -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= conf_err.c conf_lib.c conf_api.c conf_def.c conf_mod.c \
	 conf_mall.c conf_sap.c

LIBOBJ=	conf_err.o conf_lib.o conf_api.o conf_def.o conf_mod.o \
	conf_mall.o conf_sap.o

SRC= $(LIBSRC)

EXHEADER= conf.h conf_api.h
HEADER=	conf_def.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
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

clean:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

