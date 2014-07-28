#
# OpenSSL/engines/Makefile
#

DIR_engines=	engines
INCLUDES_engines= -I../include

CFLAGS_engines= $(INCLUDES_engines) $(CFLAG)
ASFLAGS_engines= $(INCLUDES_engines) $(ASFLAG)

GENERAL_engines=Makefile engines.com install.com engine_vector.mar
TEST_engines=
APPS_engines=

LIB_engines=$(TOP_engines)/libcrypto.a
LIBNAMES= 4758cca aep atalla cswift gmp chil nuron sureware ubsec padlock capi

LIBSRC_engines=	e_4758cca.c \
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
LIBOBJ_engines= e_4758cca.o \
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

SRC_engines= $(LIBSRC_engines)

EXHEADER_engines= 
HEADER_engines=	e_4758cca_err.c e_4758cca_err.h \
	e_aep_err.c e_aep_err.h \
	e_atalla_err.c e_atalla_err.h \
	e_cswift_err.c e_cswift_err.h \
	e_gmp_err.c e_gmp_err.h \
	e_chil_err.c e_chil_err.h \
	e_nuron_err.c e_nuron_err.h \
	e_sureware_err.c e_sureware_err.h \
	e_ubsec_err.c e_ubsec_err.h \
	e_capi_err.c e_capi_err.h

ALL_engines=    $(GENERAL_engines) $(SRC_engines) $(HEADER_engines)

top: top_engines
top_engines:
	(cd ..; $(MAKE) DIRS=$(DIR_engines) all)

all: all_engines
all_engines:	lib subdirs

lib:	$(LIBOBJ_engines)
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		for l in $(LIBNAMES); do \
			cat $(TOP_engines)/configure.mk $(TOP_engines)/Makefile.shared | $(MAKE) -f - \
				LIBNAME=$$l LIBEXTRAS="e_$$l*.o" \
				LIBDEPS='-L.. -lcrypto $(EX_LIBS)' \
				link_o.$(SHLIB_TARGET); \
		done; \
	else \
		$(AR) $(LIB_engines) $(LIBOBJ_engines); \
		$(RANLIB) $(LIB_engines) || echo Never mind.; \
	fi; \
	touch lib

e_padlock-x86.s:	asm/e_padlock-x86.pl
	$(PERL) asm/e_padlock-x86.pl $(PERLASM_SCHEME) $(CFLAGS_engines) $(PROCESSOR) > $@
e_padlock-x86_64.s:	asm/e_padlock-x86_64.pl
	$(PERL) asm/e_padlock-x86_64.pl $(PERLASM_SCHEME) > $@

subdirs: subdirs_engines
subdirs_engines:
	echo $(ENGDIRS)

files: files_engines
files_engines:
	$(PERL) $(TOP_engines)/util/files.pl TOP=$(TOP_engines) Makefile >> $(TOP_engines)/MINFO

# XXXXX This currently only works on systems that use .so as suffix
# for shared libraries as well as for Cygwin which uses the
# dlfcn_name_converter and therefore stores the engines with .so suffix, too.
# XXXXX This was extended to HP-UX dl targets, which use .sl suffix.
# XXXXX This was extended to mingw targets, which use eay32.dll suffix without lib as prefix.
install: install_engines
install_engines:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		$(PERL) $(TOP_engines)/util/mkdir-p.pl $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines; \
		for l in $(LIBNAMES); do \
			( echo installing $$l; \
			  pfx=lib; \
			  if ! expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
				case "$(CFLAGS_engines)" in \
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

tags: tags_engines
tags_engines:
	ctags $(SRC_engines)

errors: errors_engines
errors_engines:
	set -e; for l in $(LIBNAMES); do \
		$(PERL) ../util/mkerr.pl -conf e_$$l.ec \
			-nostatic -staticloader -write e_$$l.c; \
	done
	(cd ccgost; $(MAKE) PERL=$(PERL) errors)

tests: tests_engines
tests_engines:

lint: lint_engines
lint_engines:
	lint -DLINT $(INCLUDES_engines) $(SRC_engines)>fluff

dclean: dclean_engines
dclean_engines:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_engines
clean_engines:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_engines) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_engines) -o $@ $<
