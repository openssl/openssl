#
# OpenSSL/fips-1.0/Makefile
#

DIR=		fips-1.0
TOP=		..
CC=		cc
INCLUDE=	-I. -I$(TOP) -I../include
INCLUDES=	-I.. -I../.. -I../../include
CFLAG=		-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=	/usr/local/ssl
MAKEFILE=       Makefile
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
PERL=		perl
RM=             rm -f
AR=		ar r

PEX_LIBS=
EX_LIBS=

CFLAGS= $(INCLUDE) $(CFLAG) -DHMAC_EXT=\"$${HMAC_EXT:-sha1}\"


LIBS=

FDIRS=sha rand des aes dsa rsa dh hmac

GENERAL=Makefile README fips-lib.com install.com

LIB= $(TOP)/libcrypto.a
SHARED_LIB= libcrypto$(SHLIB_EXT)
LIBSRC=fips.c fips_err_wrapper.c fipshashes.c
LIBOBJ=fips.o fips_err_wrapper.o fipshashes.o

FIPS_OBJ_LISTS=sha/lib hmac/lib rand/lib des/lib aes/lib dsa/lib rsa/lib dh/lib

SRC= $(LIBSRC)

EXHEADER=fips.h
HEADER=$(EXHEADER) fips_err.h
EXE=fipsld
TEST=fips_test_suite.c

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:
	@if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
		$(MAKE) -e subdirs check lib shared; \
	fi

check:
#	$(PERL) ../util/checkhash.pl || (rm fipscanister.o* 2>/dev/null; exit 1)
	echo FIPS module not built: no check done

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

fipscanister.o: fips_start.o $(LIBOBJ) $(FIPS_OBJ_LISTS) fips_end.o
	@objs="fips_start.o $(LIBOBJ)"; \
	for i in $(FIPS_OBJ_LISTS); do \
		dir=`dirname $$i`; script="s|^|$$dir/|;s| | $$dir/|g"; \
		objs="$$objs `sed "$$script" $$i`"; \
	done; \
	objs="$$objs fips_end.o" ; \
	if [ -n "${FIPS_SITE_LD}" ]; then \
		set -x; ${FIPS_SITE_LD} -r -o $@ $$objs; \
	elif $(CC) -dumpversion >/dev/null 2>&1; then \
		set -x; $(CC) $(CFLAGS) -r -nostdlib -o $@ $$objs ; \
	else case "`(uname -s) 2>/dev/null`" in \
		HP-UX|OSF1|SunOS) set -x; /usr/ccs/bin/ld -r -o $@ $$objs ;; \
		*) set -x; $(CC) $(CFLAGS) -r -o $@ $$objs ;; \
	esac fi
	sha/fips_standalone_sha1 fipscanister.o > fipscanister.o.sha1

# If another exception is immediately required, assign approprite
# site-specific ld command to FIPS_SITE_LD environment variable.

fips_start.o: fips_canister.c
	$(CC) $(CFLAGS) -DFIPS_START -c -o $@ fips_canister.c
fips_end.o: fips_canister.c
	$(CC) $(CFLAGS) -DFIPS_END -c -o $@ fips_canister.c
fips_premain_dso$(EXE_EXT): fips_premain.c
	$(CC) $(CFLAGS) -DFINGERPRINT_PREMAIN_DSO_LOAD -o $@ fips_premain.c \
		../libcrypto.a $(EX_LIBS)

subdirs:
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making all in fips/$$i..." && \
	$(MAKE) CC='$(CC)' INCLUDES='${INCLUDES}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_ASM='${BN_ASM}' DES_ENC='${DES_ENC}' FIPS_DES_ENC='${FIPS_DES_ENC}' SHA1_ASM_OBJ='${SHA1_ASM_OBJ}' FIPS_SHA1_ASM_OBJ='${FIPS_SHA1_ASM_OBJ}' MD5_ASM_OBJ='${MD5_ASM_OBJ}' RMD160_ASM_OBJ='${RMD160_ASM_OBJ}' BF_ENC='${BF_ENC}' CAST_ENC='${CAST_ENC}' RC4_ENC='${RC4_ENC}' RC5_ENC='${RC5_ENC}' AR='${AR}' PROCESSOR='${PROCESSOR}' PERL='${PERL}' RANLIB='${RANLIB}' all ) || exit 1; \
	done;

sub_target:
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making $(TARGET) in fips/$$i..." && \
	$(MAKE) CC='$(CC)' INCLUDES='${INCLUDES}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_ASM='${BN_ASM}' DES_ENC='${DES_ENC}' FIPS_DES_ENC='${FIPS_DES_ENC}' SHA1_ASM_OBJ='${SHA1_ASM_OBJ}' FIPS_SHA1_ASM_OBJ='${FIPS_SHA1_ASM_OBJ}' MD5_ASM_OBJ='${MD5_ASM_OBJ}' RMD160_ASM_OBJ='${RMD160_ASM_OBJ}' BF_ENC='${BF_ENC}' CAST_ENC='${CAST_ENC}' RC4_ENC='${RC4_ENC}' RC5_ENC='${RC5_ENC}' AR='${AR}' PROCESSOR='${PROCESSOR}' PERL='${PERL}' RANLIB='${RANLIB}' $(TARGET) ) || exit 1; \
	done;

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making 'files' in fips/$$i..." && \
	$(MAKE) PERL='${PERL}' files ); \
	done;

links:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@for i in $(FDIRS); do \
	(cd $$i && echo "making links in fips/$$i..." && \
	$(MAKE) CC='$(CC)' INCLUDES='${INCLUDES}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_ASM='${BN_ASM}' DES_ENC='${DES_ENC}' FIPS_DES_ENC='${FIPS_DES_ENC}' SHA1_ASM_OBJ='${SHA1_ASM_OBJ}' FIPS_SHA1_ASM_OBJ='${FIPS_SHA1_ASM_OBJ}' MD5_ASM_OBJ='${MD5_ASM_OBJ}' RMD160_ASM_OBJ='${RMD160_ASM_OBJ}' BF_ENC='${BF_ENC}' CAST_ENC='${CAST_ENC}' RC4_ENC='${RC4_ENC}' RC5_ENC='${RC5_ENC}' AR='${AR}' PERL='${PERL}' links ); \
	done;

lib:	$(FIPSLIBDIR)/fipscanister.o
	$(AR) $(LIB) $(FIPSLIBDIR)/fipscanister.o
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

shared:	fips_premain_dso$(EXE_EXT)
	if [ -n "$(SHARED_LIBS)" ]; then \
		(cd ..; $(MAKE) FIPSLD_CC=$(CC) FIPSLD=fips-1.0/fipsld $(SHARED_LIB)); \
	fi

libs:
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making libs in fips/$$i..." && \
	$(MAKE) CC='$(CC)' CFLAG='${CFLAG}' INSTALL_PREFIX='${INSTALL_PREFIX}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' AR='${AR}' lib ); \
	done;

tests:
	(cd ..; make DIRS=test)

fips_test: top tests
	-cd testvectors && perl -p -i -e 's/COUNT=/COUNT = /' des[23]/req/*.req
	@for i in dsa sha aes des hmac rand rsa; \
	do \
		(cd $$i && echo "making fips_test in fips/$$i..." && $(MAKE) fips_test) \
	done;

install:
	@headerlist="$(EXHEADER)"; for i in $$headerlist ;\
	do \
		(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
		chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;
	@for i in $(FDIRS) ;\
	do \
		(cd $$i && echo "making install in fips/$$i..." && \
		$(MAKE) CC='$(CC)' CFLAG='${CFLAG}' INSTALL_PREFIX='${INSTALL_PREFIX}'  INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' install ); \
	done;
	@for i in $(EXE) ; \
	do \
		echo "installing $$i"; \
		cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
		chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
	done
	@cp -p -f fipscanister.o fipscanister.o.sha1 fips_premain.c \
		$(INSTALL_PREFIX)$(INSTALLTOP)/lib/; \
	strings fipscanister.o | grep "HMAC-SHA1(fips_premain\\.c)" > \
		$(INSTALL_PREFIX)$(INSTALLTOP)/lib/fips_premain.c.sha1; \
	chmod 0444 $(INSTALL_PREFIX)$(INSTALLTOP)/lib/fips*

lint:
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making lint in fips/$$i..." && \
	$(MAKE) CC='$(CC)' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' lint ); \
	done;

depend:
	if [ ! -f buildinf.h ]; then touch buildinf.h; fi # fake buildinf.h if it does not exist
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDE) $(DEPFLAG) -- $(SRC)
	if [ ! -s buildinf.h ]; then rm buildinf.h; fi
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making depend in fips/$$i..." && \
	$(MAKE) MAKEFILE='${MAKEFILE}' INCLUDES='${INCLUDES}' CFLAG='${CFLAG}' DEPFLAG='${DEPFLAG}' MAKEDEPPROG='${MAKEDEPPROG}' KRB5_INCLUDES='${KRB5_INCLUDES}' PERL='${PERL}' depend ); \
	done;

clean:
	rm -f buildinf.h *.o *.obj fips_premain_dso$(EXE_EXT) lib tags core .pure .nfs* *.old *.bak fluff
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making clean in fips/$$i..." && \
	$(MAKE) CC='$(CC)' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' clean ); \
	done;

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making dclean in fips/$$i..." && \
	$(MAKE) PERL='${PERL}' CC='$(CC)' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' dclean ); \
	done;

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips.o: ../include/openssl/aes.h ../include/openssl/asn1.h
fips.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
fips.o: ../include/openssl/bn.h ../include/openssl/cast.h
fips.o: ../include/openssl/crypto.h ../include/openssl/des.h
fips.o: ../include/openssl/des_old.h ../include/openssl/dh.h
fips.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
fips.o: ../include/openssl/err.h ../include/openssl/evp.h
fips.o: ../include/openssl/fips.h ../include/openssl/fips_rand.h
fips.o: ../include/openssl/hmac.h ../include/openssl/idea.h
fips.o: ../include/openssl/lhash.h ../include/openssl/md2.h
fips.o: ../include/openssl/md4.h ../include/openssl/md5.h
fips.o: ../include/openssl/mdc2.h ../include/openssl/obj_mac.h
fips.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
fips.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
fips.o: ../include/openssl/rand.h ../include/openssl/rc2.h
fips.o: ../include/openssl/rc4.h ../include/openssl/rc5.h
fips.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
fips.o: ../include/openssl/safestack.h ../include/openssl/sha.h
fips.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
fips.o: ../include/openssl/ui.h ../include/openssl/ui_compat.h fips.c
fips.o: fips_locl.h
fips_err_wrapper.o: ../include/openssl/opensslconf.h fips_err_wrapper.c
