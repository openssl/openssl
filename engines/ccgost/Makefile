DIR=ccgost
INCLUDES= -I../../include
CFLAGS= $(INCLUDES) $(CFLAG)
LIB=$(TOP)/libcrypto.a

TEST=gost2814789t.c

LIBSRC= gost2001.c gost2001_keyx.c gost89.c gost94_keyx.c gost_ameth.c gost_asn1.c gost_crypt.c gost_ctl.c gost_eng.c gosthash.c gost_keywrap.c gost_md.c gost_params.c gost_pmeth.c gost_sign.c

LIBOBJ= e_gost_err.o gost2001_keyx.o gost2001.o gost89.o gost94_keyx.o gost_ameth.o gost_asn1.o gost_crypt.o gost_ctl.o gost_eng.o gosthash.o gost_keywrap.o gost_md.o gost_params.o gost_pmeth.o gost_sign.o

SRC=$(LIBSRC)

LIBNAME=gost

top: top_engines_ccgost
top_engines_ccgost: 
	(cd $(TOP); $(MAKE) DIRS=engines EDIRS=$(DIR) sub_all)

all: all_engines_ccgost
all_engines_ccgost: lib

tags: tags_engines_ccgost
tags_engines_ccgost:
	ctags $(SRC)

errors: errors_engines_ccgost
errors_engines_ccgost:
	$(PERL) ../../util/mkerr.pl -conf gost.ec -nostatic -write $(SRC)

lib: lib_engines_ccgost
lib_engines_ccgost: $(LIBOBJ)
	if [ -n "$(SHARED_LIBS)" ]; then \
		cat $(TOP)/configure.mk $(TOP)/Makefile.shared | $(MAKE) -f - \
			LIBNAME=$(LIBNAME) \
			LIBEXTRAS='$(LIBOBJ)' \
			LIBDEPS='-L$(TOP) -lcrypto' \
			link_o.$(SHLIB_TARGET); \
	else \
		$(AR) $(LIB) $(LIBOBJ); \
	fi
	@touch lib

install: install_engines_ccgost
install_engines_ccgost:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(LIBNAME); \
		pfx=lib; \
		if ! expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
			case "$(CFLAGS)" in \
			*DSO_BEOS*) sfx=".so";; \
			*DSO_DLFCN*) sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;; \
			*DSO_DL*) sfx=".sl";; \
			*DSO_WIN32*) sfx="eay32.dll"; pfx=;; \
			*) sfx=".bad";; \
			esac; \
			cp $${pfx}$(LIBNAME)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		else \
			sfx=".so"; \
			cp cyg$(LIBNAME).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		fi; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx; \
	fi

links: links_engines_ccgost
links_engines_ccgost:
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)

tests: tests_engines_ccgost
tests_engines_ccgost:

files: files_engines_ccgost
files_engines_ccgost:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

lint: lint_engines_ccgost
lint_engines_ccgost:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_engines_ccgost
dclean_engines_ccgost:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_engines_ccgost
clean_engines_ccgost:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll *.dylib

