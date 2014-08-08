INCLUDES_engines_ccgost= -Iinclude
CFLAGS_engines_ccgost= $(INCLUDES_engines_ccgost) $(CFLAG)
LIB_engines_ccgost=libcrypto.a

TEST_engines_ccgost=engines/ccgost/gost2814789t.c

LIBSRC_engines_ccgost= engines/ccgost/gost2001.c engines/ccgost/gost2001_keyx.c engines/ccgost/gost89.c engines/ccgost/gost94_keyx.c engines/ccgost/gost_ameth.c engines/ccgost/gost_asn1.c engines/ccgost/gost_crypt.c engines/ccgost/gost_ctl.c engines/ccgost/gost_eng.c engines/ccgost/gosthash.c engines/ccgost/gost_keywrap.c engines/ccgost/gost_md.c engines/ccgost/gost_params.c engines/ccgost/gost_pmeth.c engines/ccgost/gost_sign.c

LIBOBJ_engines_ccgost= engines/ccgost/e_gost_err.o engines/ccgost/gost2001_keyx.o engines/ccgost/gost2001.o engines/ccgost/gost89.o engines/ccgost/gost94_keyx.o engines/ccgost/gost_ameth.o engines/ccgost/gost_asn1.o engines/ccgost/gost_crypt.o engines/ccgost/gost_ctl.o engines/ccgost/gost_eng.o engines/ccgost/gosthash.o engines/ccgost/gost_keywrap.o engines/ccgost/gost_md.o engines/ccgost/gost_params.o engines/ccgost/gost_pmeth.o engines/ccgost/gost_sign.o

SRC_engines_ccgost=$(LIBSRC_engines_ccgost)

LIBNAME_engines_ccgost=gost


all: all_engines_ccgost
all_engines_ccgost: engines/ccgost/lib

tags: tags_engines_ccgost
tags_engines_ccgost:
	ctags $(SRC_engines_ccgost)

errors: errors_engines_ccgost
errors_engines_ccgost:
	$(PERL) util/mkerr.pl -conf gost.ec -nostatic -write $(SRC_engines_ccgost)

engines/ccgost/lib: $(LIBOBJ_engines_ccgost)
	if [ -n "$(SHARED_LIBS)" ]; then \
		cat configure.mk Makefile.shared | $(MAKE) -f - \
			LIBNAME=$(LIBNAME_engines_ccgost) \
			LIBEXTRAS='$(LIBOBJ_engines_ccgost)' \
			LIBDEPS='-L. -lcrypto' \
			link_o.$(SHLIB_TARGET); \
	else \
		$(AR) $(LIB_engines_ccgost) $(LIBOBJ_engines_ccgost); \
	fi
	@touch engines/ccgost/lib

install: install_engines_ccgost
install_engines_ccgost:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(LIBNAME_engines_ccgost); \
		pfx=engines/ccgost/lib; \
		if ! expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
			case "$(CFLAGS_engines_ccgost)" in \
			*DSO_BEOS*) sfx=".so";; \
			*DSO_DLFCN*) sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;; \
			*DSO_DL*) sfx=".sl";; \
			*DSO_WIN32*) sfx="eay32.dll"; pfx=;; \
			*) sfx=".bad";; \
			esac; \
			cp $${pfx}$(LIBNAME_engines_ccgost)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME_engines_ccgost)$$sfx.new; \
		else \
			sfx=".so"; \
			cp cyg$(LIBNAME_engines_ccgost).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME_engines_ccgost)$$sfx.new; \
		fi; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME_engines_ccgost)$$sfx.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME_engines_ccgost)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME_engines_ccgost)$$sfx; \
	fi

links: links_engines_ccgost
links_engines_ccgost:
	@$(PERL) util/mklink.pl ./test $(TEST_engines_ccgost)

tests: tests_engines_ccgost
tests_engines_ccgost:

files: files_engines_ccgost
files_engines_ccgost:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

lint: lint_engines_ccgost
lint_engines_ccgost:
	lint -DLINT $(INCLUDES_engines_ccgost) $(SRC_engines_ccgost)>engines/ccgost/fluff

dclean: dclean_engines_ccgost
dclean_engines_ccgost:

clean: clean_engines_ccgost
clean_engines_ccgost:
	rm -f engines/ccgost/*.o engines/ccgost/*.d engines/ccgost/*.obj engines/ccgost/lib engines/ccgost/tags engines/ccgost/core engines/ccgost/.pure engines/ccgost/.nfs* engines/ccgost/*.old engines/ccgost/*.bak engines/ccgost/fluff engines/ccgost/*.so engines/ccgost/*.sl engines/ccgost/*.dll engines/ccgost/*.dylib

