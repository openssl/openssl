#
#  OpenSSL/iOS/Makefile
#

DIR=		iOS
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I$(TOP)/include
CFLAG=		-g -static
MAKEFILE=	Makefile
PERL=		perl
RM=		rm -f

EXE=incore_macho

CFLAGS= $(INCLUDES) $(CFLAG)

top:
	@$(MAKE) -f $(TOP)/Makefile reflect THIS=exe

exe:	fips_algvs.app/fips_algvs

incore_macho:			incore_macho.c $(TOP)/crypto/sha/sha1dgst.c
	$(HOSTCC) $(HOSTCFLAGS) -I$(TOP)/include -I$(TOP)/crypto -o $@ incore_macho.c $(TOP)/crypto/sha/sha1dgst.c

fips_algvs.app/fips_algvs:	$(TOP)/test/fips_algvs.c $(TOP)/fips/fipscanister.o fopen.m incore_macho
	FIPS_SIG=./incore_macho \
	$(TOP)/fips/fipsld $(CFLAGS) -I$(TOP)/fips -o $@ \
		$(TOP)/test/fips_algvs.c $(TOP)/fips/fipscanister.o \
		fopen.m -framework Foundation || rm $@
	codesign -f -s "iPhone Developer" --entitlements fips_algvs.app/Entitlements.plist fips_algvs.app || rm $@

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@set -e; for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@set -e; for i in $(SCRIPTS); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	 done

tags:
	ctags $(SRC)

tests:

links:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f fips_algvs.app/fips_algvs

# DO NOT DELETE THIS LINE -- make depend depends on it.

