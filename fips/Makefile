#
# OpenSSL/crypto/Makefile
#

DIR_fips=		fips
INCLUDE_fips=	-I. -I$(TOP_fips) -I../include
# INCLUDES_fips targets sudbirs!
INCLUDES_fips=	-I.. -I../.. -I../../include
RM_fips=             rm -f
ARD=		ar d
TEST_fips=		fips_test_suite.c
FIPS_TVDIR=	testvectors
FIPS_TVOK=	$$HOME/fips/tv.ok

FIPSCANLOC=	$(FIPSLIBDIR)fipscanister.o

RECURSIVE_MAKE_fips=	[ -n "$(FDIRS)" ] && for i in $(FDIRS) ; do \
		    (cd $$i && echo "making $$target in $(DIR_fips)/$$i..." && \
		    $(MAKE) -e TOP=../.. DIR=$$i INCLUDES_fips_$$i='${INCLUDES_fips}' $$target ) || exit 1; \
		done;

 
CFLAGS_fips= $(INCLUDE_fips) $(CFLAG) -DHMAC_EXT=\"$${HMAC_EXT:-sha1}\"
ASFLAGS_fips= $(INCLUDE_fips) $(ASFLAG)
AFLAGS_fips=$(ASFLAGS_fips)

LIBS_fips=

FDIRS=sha rand des aes dsa ecdh ecdsa rsa dh cmac hmac utl

GENERAL_fips=Makefile README fips-lib.com install.com

LIB_fips= $(TOP_fips)/libcrypto.a
SHARED_LIB_fips= $(FIPSCANLIB)$(SHLIB_EXT)
LIBSRC_fips=fips.c fips_post.c
LIBOBJ_fips=fips.o fips_post.o

FIPS_OBJ_LISTS=sha/lib hmac/lib rand/lib des/lib aes/lib dsa/lib rsa/lib \
		dh/lib utl/lib ecdsa/lib ecdh/lib cmac/lib

SRC_fips= $(LIBSRC_fips)

EXHEADER_fips=fips.h fipssyms.h
HEADER_fips=$(EXHEADER_fips) fips_utl.h fips_locl.h fips_auth.h
EXE_fips=fipsld fips_standalone_sha1

ALL_fips=    $(GENERAL_fips) $(SRC_fips) $(HEADER_fips)

top: top_fips
top_fips:
	@(cd ..; $(MAKE) DIRS=$(DIR_fips) all)

testapps:
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP_fips)/Makefile reflect THIS=$@; fi

all: all_fips

# Idea behind fipscanister.o is to "seize" the sequestered code between
# known symbols for fingerprinting purposes, which would be commonly
# done with ld -r start.o ... end.o. The latter however presents a minor
# challenge on multi-ABI platforms. As just implied, we'd rather use ld,
# but the trouble is that we don't generally know how ABI-selection
# compiler flag is translated to corresponding linker flag. All compiler
# drivers seem to recognize -r flag and pass it down to linker, but some
# of them, including gcc, erroneously add -lc, as well as run-time
# components, such as crt1.o and alike. Fortunately among those vendor
# compilers which were observed to misinterpret -r flag multi-ABI ones
# are equipped with smart linkers, which don't require any ABI-selection
# flag and simply assume that all objects are of the same type as first
# one in command line. So the idea is to identify gcc and deficient
# vendor compiler drivers...

fipscanister.o: fips_start.o $(LIBOBJ_fips) $(FIPS_OBJ_LISTS) fips_end.o
	FIPS_ASM=""; \
	list="$(BN_ASM)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM ../crypto/bn/$$i" ; done; \
	list="$(AES_ENC)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM ../crypto/aes/$$i" ; done; \
	list="$(DES_ENC)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM ../crypto/des/$$i" ; done; \
	list="$(SHA1_ASM_OBJ)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM ../crypto/sha/$$i" ; done; \
	list="$(MODES_ASM_OBJ)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM ../crypto/modes/$$i" ; done; \
	CPUID=""; \
	list="$(CPUID_OBJ)"; for i in $$list; do CPUID="$$CPUID ../crypto/$$i" ; done; \
	objs="fips_start.o $(LIBOBJ_fips) $(FIPS_EX_OBJ) $$CPUID $$FIPS_ASM"; \
	for i in $(FIPS_OBJ_LISTS); do \
		dir=`dirname $$i`; script="s|^|$$dir/|;s| | $$dir/|g"; \
		objs="$$objs `sed "$$script" $$i`"; \
	done; \
	objs="$$objs fips_end.o" ; \
	os="`(uname -s) 2>/dev/null`"; cflags="$(CFLAGS_fips)"; \
	case "$$os" in \
		AIX)	cflags="$$cflags -Wl,-bnoobjreorder" ;; \
		HP-UX)	cflags="$$cflags -Wl,+sectionmerge"  ;; \
	esac; \
	if [ -n "${FIPS_SITE_LD}" ]; then \
		set -x; ${FIPS_SITE_LD} -r -o $@ $$objs; \
	elif $(CC) -dumpversion >/dev/null 2>&1; then \
		set -x; $(CC) $$cflags -r -nostdlib -o $@ $$objs ; \
	else case "$$os" in \
		OSF1|SunOS) set -x; /usr/ccs/bin/ld -r -o $@ $$objs ;; \
		*) set -x; $(CC) $$cflags -r -o $@ $$objs ;; \
	esac fi
	./fips_standalone_sha1$(EXE_EXT) fipscanister.o > fipscanister.o.sha1

# If another exception is immediately required, assign approprite
# site-specific ld command to FIPS_SITE_LD environment variable.

fips_start.o: fips_canister.c
	$(CC) $(CFLAGS_fips) -DFIPS_START -c -o $@ fips_canister.c
fips_end.o: fips_canister.c
	$(CC) $(CFLAGS_fips) -DFIPS_END -c -o $@ fips_canister.c
fips_premain_dso$(EXE_EXT): fips_premain.c
	$(CC) $(CFLAGS_fips) -DFINGERPRINT_PREMAIN_DSO_LOAD -o $@ fips_premain.c \
		$(FIPSLIBDIR)fipscanister.o ../libcrypto.a $(EX_LIBS)

subdirs: subdirs_fips
subdirs_fips:
	@target=all; $(RECURSIVE_MAKE_fips)

files: files_fips
files_fips:
	$(PERL) $(TOP_fips)/util/files.pl TOP=$(TOP_fips) Makefile >> $(TOP_fips)/MINFO
	@target=files; $(RECURSIVE_MAKE_fips)

links: links_fips
links_fips:
	@$(PERL) $(TOP_fips)/util/mklink.pl ../include/openssl $(EXHEADER_fips)
	@$(PERL) $(TOP_fips)/util/mklink.pl ../test $(TEST_fips)
	@target=links; $(RECURSIVE_MAKE_fips)

# lib: and $(LIB_fips): are splitted to avoid end-less loop
lib:	$(LIB_fips)
	if [ "$(FIPSCANISTERINTERNAL)" = "n" -a -n "$(FIPSCANLOC)" ]; then $(AR) ../$(FIPSCANLIB).a $(FIPSCANLOC); fi
	@touch lib

$(LIB_fips):	$(FIPSLIBDIR)fipscanister.o
	$(AR) $(LIB_fips) $(FIPSLIBDIR)fipscanister.o
	$(RANLIB) $(LIB_fips) || echo Never mind.

$(FIPSCANLIB):	$(FIPSCANLOC)
	$(AR) ../$(FIPSCANLIB).a $(FIPSCANLOC)
	if [ "$(FIPSCANLIB)" = "libfips" ]; then \
		$(AR) $(LIB_fips) $(FIPSCANLOC) ; \
		$(RANLIB) $(LIB_fips) || echo Never Mind. ; \
	fi
	$(RANLIB) ../$(FIPSCANLIB).a || echo Never mind.
	@touch lib

shared: shared_fips
shared_fips:	lib subdirs_fips fips_premain_dso$(EXE_EXT)

libs: libs_fips
libs_fips:
	@target=lib; $(RECURSIVE_MAKE_fips)

fips_test: fips_test_fips
fips_test_fips: top
	@target=fips_test; $(RECURSIVE_MAKE_fips)

fips_test_diff:
	@if diff -b -B -I '^\#' -cr -X fips-nodiff.txt $(FIPS_TVDIR) $(FIPS_TVOK) ; then \
		echo "FIPS diff OK" ; \
	else \
		echo "***FIPS DIFF ERROR***" ; exit 1 ; \
	fi


install: install_fips
install_fips:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_fips)"; for i in $$headerlist ;\
	do \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;
	@target=install; $(RECURSIVE_MAKE_fips)
	for i in $(EXE_fips) ; \
	do \
		echo "installing $$i"; \
		cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
		chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
	done
	cp -p -f $(FIPSLIBDIR)fipscanister.o $(FIPSLIBDIR)fipscanister.o.sha1 \
		$(FIPSLIBDIR)fips_premain.c $(FIPSLIBDIR)fips_premain.c.sha1 \
		$(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/; \
	chmod 0444 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/fips*

lint: lint_fips
lint_fips:
	@target=lint; $(RECURSIVE_MAKE_fips)

clean: clean_fips
clean_fips:
	rm -f fipscanister.o.sha1 fips_premain_dso$(EXE_EXT) fips_standalone_sha1$(EXE_EXT) \
		*.s *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
	@target=clean; $(RECURSIVE_MAKE_fips)

dclean: dclean_fips
dclean_fips:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	@target=dclean; $(RECURSIVE_MAKE_fips)

.c.o:
	$(CC) $(CFLAGS_fips) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips) -o $@ $<
