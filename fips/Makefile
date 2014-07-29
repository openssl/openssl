#
# OpenSSL/crypto/Makefile
#

INCLUDE_fips=	-Ifips -I. -Iinclude
# INCLUDES_fips targets sudbirs!
INCLUDES_fips=	-Ifips -I. -Iinclude
RM_fips=             rm -f
ARD=		ar d
TEST_fips=		fips/fips_test_suite.c
FIPS_TVDIR=	testvectors
FIPS_TVOK=	$$HOME/fips/tv.ok

FIPSCANLOC=	$(FIPSLIBDIR)fipscanister.o

CFLAGS_fips= $(INCLUDE_fips) $(CFLAG) -DHMAC_EXT=\"$${HMAC_EXT:-sha1}\"
ASFLAGS_fips= $(INCLUDE_fips) $(ASFLAG)
AFLAGS_fips=$(ASFLAGS_fips)

LIBS_fips=

FDIRS=sha rand des aes dsa ecdh ecdsa rsa dh cmac hmac utl

GENERAL_fips=fips/Makefile fips/README fips/fips-lib.com fips/install.com

LIB_fips= libcrypto.a
SHARED_LIB_fips= $(FIPSCANLIB)$(SHLIB_EXT)
LIBSRC_fips=fips/fips.c fips/fips_post.c
LIBOBJ_fips=fips/fips.o fips/fips_post.o

FIPS_OBJ_LISTS=fips/sha/lib fips/hmac/lib fips/rand/lib fips/des/lib fips/aes/lib fips/dsa/lib fips/rsa/lib \
		fips/dh/lib fips/utl/lib fips/ecdsa/lib fips/ecdh/lib fips/cmac/lib

SRC_fips= $(LIBSRC_fips)

EXHEADER_fips=fips/fips.h fips/fipssyms.h
HEADER_fips=$(EXHEADER_fips) fips/fips_utl.h fips/fips_locl.h fips/fips_auth.h
EXE_fips=fips/fipsld fips/fips_standalone_sha1

ALL_fips=    $(GENERAL_fips) $(SRC_fips) $(HEADER_fips)


fips/testapps:
	@if [ -z "$(THIS)" ]; then $(MAKE) -f Makefile reflect THIS=$@; fi

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

fips/fipscanister.o: fips/fips_start.o $(LIBOBJ_fips) $(FIPS_OBJ_LISTS) fips/fips_end.o
	FIPS_ASM=""; \
	list="$(BN_ASM)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM $$i" ; done; \
	list="$(AES_ENC)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM $$i" ; done; \
	list="$(DES_ENC)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM $$i" ; done; \
	list="$(SHA1_ASM_OBJ)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM $$i" ; done; \
	list="$(MODES_ASM_OBJ)"; for i in $$list; do FIPS_ASM="$$FIPS_ASM $$i" ; done; \
	CPUID=""; \
	list="$(CPUID_OBJ)"; for i in $$list; do CPUID="$$CPUID $$i" ; done; \
	objs=fips/"fips_start.o $(LIBOBJ_fips) $(FIPS_EX_OBJ) $$CPUID $$FIPS_ASM"; \
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
	$(EXE_EXT) fips/fipscanister.o > fipscanister.o.sha1

# If another exception is immediately required, assign approprite
# site-specific ld command to FIPS_SITE_LD environment variable.

fips/fips_start.o: fips/fips_canister.c
	$(CC) $(CFLAGS_fips) -DFIPS_START -c -o $@ fips/fips_canister.c
fips/fips_end.o: fips/fips_canister.c
	$(CC) $(CFLAGS_fips) -DFIPS_END -c -o $@ fips/fips_canister.c
fips/fips_premain_dso$(EXE_EXT): fips/fips_premain.c
	$(CC) $(CFLAGS_fips) -DFINGERPRINT_PREMAIN_DSO_LOAD -o $@ fips/fips_premain.c \
		$(FIPSLIBDIR)fipscanister.o ./libcrypto.a $(EX_LIBS)

files: files_fips
files_fips:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips
links_fips:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips)
	@$(PERL) util/mklink.pl ./test $(TEST_fips)

# lib: and $(LIB_fips): are splitted to avoid end-less loop
fips/lib:	$(LIB_fips)
	if [ "$(FIPSCANISTERINTERNAL)" = "n" -a -n "$(FIPSCANLOC)" ]; then $(AR) $(FIPSCANLIB).a $(FIPSCANLOC); fi
	@touch fips/lib

$(LIB_fips):	$(FIPSLIBDIR)fipscanister.o
	$(AR) $(LIB_fips) $(FIPSLIBDIR)fipscanister.o
	$(RANLIB) $(LIB_fips) || echo Never mind.

$(FIPSCANLIB):	$(FIPSCANLOC)
	$(AR) $(FIPSCANLIB).a $(FIPSCANLOC)
	if [ "$(FIPSCANLIB)" = "libfips" ]; then \
		$(AR) $(LIB_fips) $(FIPSCANLOC) ; \
		$(RANLIB) $(LIB_fips) || echo Never Mind. ; \
	fi
	$(RANLIB) $(FIPSCANLIB).a || echo Never mind.
	@touch fips/lib

shared: shared_fips
shared_fips:	fips/lib subdirs_fips fips/fips_premain_dso$(EXE_EXT)

fips_test: fips_test_fips
fips_test_fips: all_fips

fips/fips_test_diff:
	@if diff -b -B -I '^\#' -cr -X fips-nodiff.txt $(FIPS_TVDIR) $(FIPS_TVOK) ; then \
		echo "FIPS diff OK" ; \
	else \
		echo "***FIPS DIFF ERROR***" ; exit 1 ; \
	fi


install: install_fips
fips/install_fips_before_subdirs:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_fips)"; for i in $$headerlist ;\
	do \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

install_fips: fips/install_fips_subdirs
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

clean: clean_fips
clean_fips:
	rm -f fips/fipscanister.o.sha1 fips/fips_premain_dso$(EXE_EXT) fips/fips_standalone_sha1$(EXE_EXT) \
		fips/*.s fips/*.o fips/*.d */*.o */*.d fips/*.obj fips/lib fips/tags fips/core fips/.pure fips/.nfs* fips/*.old fips/*.bak fips/fluff

dclean: dclean_fips
dclean_fips:

.c.o:
	$(CC) $(CFLAGS_fips) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips) -o $@ $<
