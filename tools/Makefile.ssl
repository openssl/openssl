#
# SSLeay/tools/Makefile
#

DIR=	tools
TOP=	..
CC=	cc
INCLUDES= -I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile.ssl
TEST=
APPS= c_rehash
MISC_APPS= c_hash c_info c_issuer c_name

all:

install:
	@for i in $(APPS) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	done;
	@for i in $(MISC_APPS) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	done;

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile

lint:

tags:

errors:

depend:

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

errors:

# DO NOT DELETE THIS LINE -- make depend depends on it.
