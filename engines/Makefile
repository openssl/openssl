#
# OpenSSL/engines/Makefile
#

INCLUDES_engines= -Iinclude

CFLAGS_engines= $(INCLUDES_engines) $(CFLAG)
ASFLAGS_engines= $(INCLUDES_engines) $(ASFLAG)

GENERAL_engines=engines/Makefile engines/engines.com engines/install.com engines/engine_vector.mar
TEST_engines=
APPS_engines=

LIB_engines=libcrypto.a
LIBNAMES= 4758cca aep atalla cswift gmp chil nuron sureware ubsec padlock capi

LIBSRC_engines=	engines/e_4758cca.c \
	engines/e_aep.c \
	engines/e_atalla.c \
	engines/e_cswift.c \
	engines/e_gmp.c \
	engines/e_chil.c \
	engines/e_nuron.c \
	engines/e_sureware.c \
	engines/e_ubsec.c \
	engines/e_padlock.c \
	engines/e_capi.c
LIBOBJ_engines= engines/e_4758cca.o \
	engines/e_aep.o \
	engines/e_atalla.o \
	engines/e_cswift.o \
	engines/e_gmp.o \
	engines/e_chil.o \
	engines/e_nuron.o \
	engines/e_sureware.o \
	engines/e_ubsec.o \
	engines/e_padlock.o \
	engines/e_capi.o \
	$(ENGINES_ASM_OBJ)

SRC_engines= $(LIBSRC_engines)

EXHEADER_engines= 
HEADER_engines=	engines/e_4758cca_err.c engines/e_4758cca_err.h \
	engines/e_aep_err.c engines/e_aep_err.h \
	engines/e_atalla_err.c engines/e_atalla_err.h \
	engines/e_cswift_err.c engines/e_cswift_err.h \
	engines/e_gmp_err.c engines/e_gmp_err.h \
	engines/e_chil_err.c engines/e_chil_err.h \
	engines/e_nuron_err.c engines/e_nuron_err.h \
	engines/e_sureware_err.c engines/e_sureware_err.h \
	engines/e_ubsec_err.c engines/e_ubsec_err.h \
	engines/e_capi_err.c engines/e_capi_err.h

ALL_engines=    $(GENERAL_engines) $(SRC_engines) $(HEADER_engines)


all: all_engines
all_engines:	engines/lib engines/subdirs

engines/lib:	$(LIBOBJ_engines)
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		for l in $(LIBNAMES); do \
			cat configure.mk Makefile.shared | $(MAKE) -f - \
				LIBNAME=$$l LIBEXTRAS="e_$$l*.o" \
				LIBDEPS='-L.. -lcrypto $(EX_LIBS)' \
				link_o.$(SHLIB_TARGET); \
		done; \
	else \
		$(AR) $(LIB_engines) $(LIBOBJ_engines); \
		$(RANLIB) $(LIB_engines) || echo Never mind.; \
	fi; \
	touch engines/lib

engines/e_padlock-x86.s:	engines/asm/e_padlock-x86.pl
	$(PERL) engines/asm/e_padlock-x86.pl $(PERLASM_SCHEME) $(CFLAGS_engines) $(PROCESSOR) > $@
engines/e_padlock-x86_64.s:	engines/asm/e_padlock-x86_64.pl
	$(PERL) engines/asm/e_padlock-x86_64.pl $(PERLASM_SCHEME) > $@

engines/subdirs: subdirs_engines
subdirs_engines:
	echo $(ENGDIRS)

files: files_engines
files_engines:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

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
		$(PERL) util/mkdir-p.pl $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines; \
		for l in $(LIBNAMES); do \
			( echo installing $$l; \
			  pfx=engines/lib; \
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
		$(PERL) util/mkerr.pl -conf e_$$l.ec \
			-nostatic -staticloader -write engines/e_$$l.c; \
	done
	(cd ccgost; $(MAKE) PERL=$(PERL) errors)

tests: tests_engines
tests_engines:

lint: lint_engines
lint_engines:
	lint -DLINT $(INCLUDES_engines) $(SRC_engines)>engines/fluff

dclean: dclean_engines
dclean_engines:

clean: clean_engines
clean_engines:
	rm -f engines/*.o engines/*.d engines/*.obj engines/lib engines/tags engines/core engines/.pure engines/.nfs* engines/*.old engines/*.bak engines/fluff

