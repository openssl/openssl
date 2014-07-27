INCLUDES_engines_ccgost= -I../../include
CFLAGS_engines_ccgost= $(INCLUDES_engines_ccgost) $(CFLAG)
LIB_engines_ccgost=$(TOP_engines_ccgost)/libcrypto.a

TEST_engines_ccgost=gost2814789t.c

LIBSRC_engines_ccgost= gost2001.c gost2001_keyx.c gost89.c gost94_keyx.c gost_ameth.c gost_asn1.c gost_crypt.c gost_ctl.c gost_eng.c gosthash.c gost_keywrap.c gost_md.c gost_params.c gost_pmeth.c gost_sign.c

LIBOBJ_engines_ccgost= e_gost_err.o gost2001_keyx.o gost2001.o gost89.o gost94_keyx.o gost_ameth.o gost_asn1.o gost_crypt.o gost_ctl.o gost_eng.o gosthash.o gost_keywrap.o gost_md.o gost_params.o gost_pmeth.o gost_sign.o

SRC_engines_ccgost=$(LIBSRC_engines_ccgost)

LIBNAME_engines_ccgost=gost


all: all_engines_ccgost
all_engines_ccgost: lib

tags: tags_engines_ccgost
tags_engines_ccgost:
	ctags $(SRC_engines_ccgost)

errors: errors_engines_ccgost
errors_engines_ccgost:
	$(PERL) ../../util/mkerr.pl -conf gost.ec -nostatic -write $(SRC_engines_ccgost)

lib: $(LIBOBJ_engines_ccgost)
	if [ -n "$(SHARED_LIBS)" ]; then \
		cat $(TOP_engines_ccgost)/configure.mk $(TOP_engines_ccgost)/Makefile.shared | $(MAKE) -f - \
			LIBNAME=$(LIBNAME_engines_ccgost) \
			LIBEXTRAS='$(LIBOBJ_engines_ccgost)' \
			LIBDEPS='-L$(TOP_engines_ccgost) -lcrypto' \
			link_o.$(SHLIB_TARGET); \
	else \
		$(AR) $(LIB_engines_ccgost) $(LIBOBJ_engines_ccgost); \
	fi
	@touch lib

install: install_engines_ccgost
install_engines_ccgost:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(LIBNAME_engines_ccgost); \
		pfx=lib; \
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
	@$(PERL) $(TOP_engines_ccgost)/util/mklink.pl ../../test $(TEST_engines_ccgost)

tests: tests_engines_ccgost
tests_engines_ccgost:

files: files_engines_ccgost
files_engines_ccgost:
	$(PERL) $(TOP_engines_ccgost)/util/files.pl TOP=$(TOP_engines_ccgost) Makefile >> $(TOP_engines_ccgost)/MINFO

lint: lint_engines_ccgost
lint_engines_ccgost:
	lint -DLINT $(INCLUDES_engines_ccgost) $(SRC_engines_ccgost)>fluff

dclean: dclean_engines_ccgost
dclean_engines_ccgost:

clean: clean_engines_ccgost
clean_engines_ccgost:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll *.dylib

.c.o:
	$(CC) $(CFLAGS_engines_ccgost) $(CPPFLAGS) -c -o $@ $<
