#
# OpenSSL/engines/Makefile
#

DIR=	engines
INCLUDES= -I../include

RECURSIVE_MAKE=	[ -z "$(ENGDIRS)" ] || for i in $(ENGDIRS) ; do \
		    (cd $$i && echo "making $$target in $(DIR)/$$i..." && \
		    $(MAKE) -e TOP=../.. DIR=$$i $$target ) || exit 1; \
		done;



CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)

GENERAL=Makefile engines.com install.com engine_vector.mar
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBNAMES= 4758cca aep atalla cswift gmp chil nuron sureware ubsec padlock capi

LIBSRC=	e_4758cca.c \
	e_aep.c \
	e_atalla.c \
	e_cswift.c \
	e_gmp.c \
	e_chil.c \
	e_nuron.c \
	e_sureware.c \
	e_ubsec.c \
	e_padlock.c \
	e_capi.c
LIBOBJ= e_4758cca.o \
	e_aep.o \
	e_atalla.o \
	e_cswift.o \
	e_gmp.o \
	e_chil.o \
	e_nuron.o \
	e_sureware.o \
	e_ubsec.o \
	e_padlock.o \
	e_capi.o \
	$(ENGINES_ASM_OBJ)

SRC= $(LIBSRC)

EXHEADER= 
HEADER=	e_4758cca_err.c e_4758cca_err.h \
	e_aep_err.c e_aep_err.h \
	e_atalla_err.c e_atalla_err.h \
	e_cswift_err.c e_cswift_err.h \
	e_gmp_err.c e_gmp_err.h \
	e_chil_err.c e_chil_err.h \
	e_nuron_err.c e_nuron_err.h \
	e_sureware_err.c e_sureware_err.h \
	e_ubsec_err.c e_ubsec_err.h \
	e_capi_err.c e_capi_err.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	lib subdirs

lib:	$(LIBOBJ)
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		for l in $(LIBNAMES); do \
			cat $(TOP)/configure.mk $(TOP)/Makefile.shared | $(MAKE) -f - \
				LIBNAME=$$l LIBEXTRAS="e_$$l*.o" \
				LIBDEPS='-L.. -lcrypto $(EX_LIBS)' \
				link_o.$(SHLIB_TARGET); \
		done; \
	else \
		$(AR) $(LIB) $(LIBOBJ); \
		$(RANLIB) $(LIB) || echo Never mind.; \
	fi; \
	touch lib

e_padlock-x86.s:	asm/e_padlock-x86.pl
	$(PERL) asm/e_padlock-x86.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
e_padlock-x86_64.s:	asm/e_padlock-x86_64.pl
	$(PERL) asm/e_padlock-x86_64.pl $(PERLASM_SCHEME) > $@

subdirs:
	echo $(EDIRS)
	@target=all; $(RECURSIVE_MAKE)

files:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO
	@target=files; $(RECURSIVE_MAKE)

links:
	@target=links; $(RECURSIVE_MAKE)

# XXXXX This currently only works on systems that use .so as suffix
# for shared libraries as well as for Cygwin which uses the
# dlfcn_name_converter and therefore stores the engines with .so suffix, too.
# XXXXX This was extended to HP-UX dl targets, which use .sl suffix.
# XXXXX This was extended to mingw targets, which use eay32.dll suffix without lib as prefix.
install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		$(PERL) $(TOP)/util/mkdir-p.pl $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines; \
		for l in $(LIBNAMES); do \
			( echo installing $$l; \
			  pfx=lib; \
			  if ! expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
				case "$(CFLAGS)" in \
				*DSO_BEOS*)	sfx=".so";;	\
				*DSO_DLFCN*)	sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;;	\
				*DSO_DL*)	sfx=".sl";;	\
				*DSO_WIN32*)	sfx="eay32.dll"; pfx=;;	\
				*)		sfx=".bad";;	\
				esac; \
				cp $$pfx$$l$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx.new; \
			  else \
				sfx=".so"; \
				cp cyg$$l.dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx.new; \
			  fi; \
			  chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx.new; \
			  mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx ); \
		done; \
	fi
	@target=install; $(RECURSIVE_MAKE)

tags:
	ctags $(SRC)

errors:
	set -e; for l in $(LIBNAMES); do \
		$(PERL) ../util/mkerr.pl -conf e_$$l.ec \
			-nostatic -staticloader -write e_$$l.c; \
	done
	(cd ccgost; $(MAKE) PERL=$(PERL) errors)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff
	@target=lint; $(RECURSIVE_MAKE)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	@target=dclean; $(RECURSIVE_MAKE)

clean:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
	@target=clean; $(RECURSIVE_MAKE)

