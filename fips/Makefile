#
# SSLeay/fips/Makefile
#

DIR=		fips
TOP=		..
CC=		cc
INCLUDE=	-I. -I$(TOP) -I../include
INCLUDES=	-I.. -I../.. -I../../include
CFLAG=		-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=	/usr/local/ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=       Makefile
RM=             rm -f
AR=		ar r

PEX_LIBS=
EX_LIBS=

CFLAGS= $(INCLUDE) $(CFLAG)


LIBS=

FDIRS=sha1 rand des aes dsa rsa dh

GENERAL=Makefile README fips-lib.com install.com

LIB= $(TOP)/libcrypto.a
SHARED_LIB= libcrypto$(SHLIB_EXT)
LIBSRC=fips.c fips_err_wrapper.c
LIBOBJ=fips.o fips_err_wrapper.o

SRC= $(LIBSRC)

EXHEADER=fips.h
HEADER=$(EXHEADER) fips_err.h
EXE=openssl_fips_fingerprint

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:
	@if egrep 'define OPENSSL_FIPS' $(TOP)/include/openssl/opensslconf.h > /dev/null; then \
		$(MAKE) -e subdirs check lib shared; \
	fi

check:
	TOP=`pwd`/$(TOP) ./fips_check_sha1 fingerprint.sha1 $(SRC) $(HEADER)

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
	@$(PERL) $(TOP)/util/mklink.pl ../include/openssl $(EXHEADER)
	@for i in $(FDIRS); do \
	(cd $$i && echo "making links in fips/$$i..." && \
	$(MAKE) CC='$(CC)' INCLUDES='${INCLUDES}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_ASM='${BN_ASM}' DES_ENC='${DES_ENC}' FIPS_DES_ENC='${FIPS_DES_ENC}' SHA1_ASM_OBJ='${SHA1_ASM_OBJ}' FIPS_SHA1_ASM_OBJ='${FIPS_SHA1_ASM_OBJ}' MD5_ASM_OBJ='${MD5_ASM_OBJ}' RMD160_ASM_OBJ='${RMD160_ASM_OBJ}' BF_ENC='${BF_ENC}' CAST_ENC='${CAST_ENC}' RC4_ENC='${RC4_ENC}' RC5_ENC='${RC5_ENC}' AR='${AR}' PERL='${PERL}' links ); \
	done;

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

shared:
	if [ -n "$(SHARED_LIBS)" ]; then \
		(cd ..; $(MAKE) $(SHARED_LIB)); \
	fi

libs:
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making libs in fips/$$i..." && \
	$(MAKE) CC='$(CC)' CFLAG='${CFLAG}' INSTALL_PREFIX='${INSTALL_PREFIX}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' AR='${AR}' lib ); \
	done;

tests:
	@for i in $(FDIRS) ;\
	do \
	(cd $$i && echo "making tests in fips/$$i..." && \
	$(MAKE) CC='$(CC)' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' AR='${AR}' tests ); \
	done;

top_fips_test_suite:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=. TARGET=fips_test_suite sub_target)

fips_test_suite: fips_test_suite.o $(TOP)/libcrypto.a
	$(CC) $(CFLAGS) -o fips_test_suite fips_test_suite.o $(PEX_LIBS) $(TOP)/libcrypto.a $(EX_LIBS)
	TOP=$(TOP) $(TOP)/fips/openssl_fips_fingerprint $(TOP)/libcrypto.a fips_test_suite || { rm fips_test_suite; false; }

fips_test: top top_fips_test_suite
	cd testvectors && perl -p -i -e 's/COUNT=/COUNT = /' des[23]/req/*.req
	@for i in dsa sha1 aes des ; \
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
	rm -f buildinf.h *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
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
