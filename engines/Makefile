#
# OpenSSL/engines/Makefile
#

#The following engines have been disabled as they currently do not build
# sureware ubsec

DIR=	engines
TOP=	..
CC=	cc
INCLUDES= -I../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r
ENGDIRS= ccgost

RECURSIVE_MAKE=	[ -z "$(ENGDIRS)" ] || for i in $(ENGDIRS) ; do \
		    (cd $$i && echo "making $$target in $(DIR)/$$i..." && \
		    $(MAKE) -e TOP=../.. DIR=$$i $$target ) || exit 1; \
		done;

ENGINES_ASM_OBJ=

PEX_LIBS=
EX_LIBS=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile engines.com install.com engine_vector.mar

LIB=$(TOP)/libcrypto.a
LIBNAMES= gmp padlock capi dasync
LIBSRC=	e_gmp.c \
	e_padlock.c \
	e_capi.c \
	e_dasync.c
LIBOBJ= e_gmp.o \
	e_padlock.o \
	e_capi.o \
	e_dasync.o \
	$(ENGINES_ASM_OBJ)

TESTLIBNAMES= ossltest
TESTLIBSRC= e_ossltest.c
TESTLIBOBJ= e_ossltest.o

SRC= $(LIBSRC)

HEADER=	e_gmp_err.c e_gmp_err.h \
	e_chil_err.c e_chil_err.h \
	e_ubsec_err.c e_ubsec_err.h \
	e_capi_err.c e_capi_err.h \
	e_ossltest_err.c e_ossltest_err.h \
	e_dasync_err.c e_dasync_err.h

ALL=	$(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	lib subdirs

lib:	$(LIBOBJ) $(TESTLIBOBJ)
	@if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		for l in $(LIBNAMES) $(TESTLIBNAMES); do \
			$(MAKE) -f ../Makefile.shared -e \
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
	@target=all; $(RECURSIVE_MAKE)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO
	@target=files; $(RECURSIVE_MAKE)

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
			  if expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
				sfx=".so"; \
				cp cyg$$l.dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx.new; \
			  else \
				case "$(CFLAGS)" in \
				*DSO_DLFCN*)	sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;;	\
				*DSO_DL*)	sfx=".sl";;	\
				*DSO_WIN32*)	sfx="eay32.dll"; pfx=;;	\
				*)		sfx=".bad";;	\
				esac; \
				cp $$pfx$$l$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$$pfx$$l$$sfx.new; \
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

update: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
	@[ -z "$(THIS)" ] || (set -e; target=update; $(RECURSIVE_MAKE) )

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
	@[ -z "$(THIS)" ] || (set -e; target=depend; $(RECURSIVE_MAKE) )
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC) $(TESTLIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	@target=dclean; $(RECURSIVE_MAKE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
	@target=clean; $(RECURSIVE_MAKE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

e_capi.o: ../include/openssl/asn1.h ../include/openssl/bio.h
e_capi.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
e_capi.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
e_capi.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
e_capi.o: ../include/openssl/engine.h ../include/openssl/evp.h
e_capi.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
e_capi.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
e_capi.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
e_capi.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
e_capi.o: ../include/openssl/sha.h ../include/openssl/stack.h
e_capi.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
e_capi.o: ../include/openssl/x509_vfy.h e_capi.c
e_dasync.o: ../include/openssl/asn1.h ../include/openssl/async.h
e_dasync.o: ../include/openssl/bio.h ../include/openssl/bn.h
e_dasync.o: ../include/openssl/buffer.h ../include/openssl/crypto.h
e_dasync.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
e_dasync.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
e_dasync.o: ../include/openssl/engine.h ../include/openssl/err.h
e_dasync.o: ../include/openssl/evp.h ../include/openssl/lhash.h
e_dasync.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
e_dasync.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
e_dasync.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
e_dasync.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
e_dasync.o: ../include/openssl/sha.h ../include/openssl/stack.h
e_dasync.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
e_dasync.o: ../include/openssl/x509_vfy.h e_dasync.c e_dasync_err.c
e_dasync.o: e_dasync_err.h
e_gmp.o: ../include/openssl/asn1.h ../include/openssl/bio.h
e_gmp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
e_gmp.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
e_gmp.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
e_gmp.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
e_gmp.o: ../include/openssl/evp.h ../include/openssl/lhash.h
e_gmp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
e_gmp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
e_gmp.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
e_gmp.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
e_gmp.o: ../include/openssl/sha.h ../include/openssl/stack.h
e_gmp.o: ../include/openssl/symhacks.h ../include/openssl/x509.h
e_gmp.o: ../include/openssl/x509_vfy.h e_gmp.c
e_ossltest.o: ../include/openssl/aes.h ../include/openssl/asn1.h
e_ossltest.o: ../include/openssl/bio.h ../include/openssl/buffer.h
e_ossltest.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
e_ossltest.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
e_ossltest.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
e_ossltest.o: ../include/openssl/err.h ../include/openssl/evp.h
e_ossltest.o: ../include/openssl/lhash.h ../include/openssl/md5.h
e_ossltest.o: ../include/openssl/modes.h ../include/openssl/obj_mac.h
e_ossltest.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
e_ossltest.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
e_ossltest.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
e_ossltest.o: ../include/openssl/safestack.h ../include/openssl/sha.h
e_ossltest.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
e_ossltest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
e_ossltest.o: e_ossltest.c e_ossltest_err.c e_ossltest_err.h
e_padlock.o: ../include/openssl/aes.h ../include/openssl/asn1.h
e_padlock.o: ../include/openssl/bio.h ../include/openssl/buffer.h
e_padlock.o: ../include/openssl/crypto.h ../include/openssl/dso.h
e_padlock.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
e_padlock.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
e_padlock.o: ../include/openssl/engine.h ../include/openssl/err.h
e_padlock.o: ../include/openssl/evp.h ../include/openssl/lhash.h
e_padlock.o: ../include/openssl/modes.h ../include/openssl/obj_mac.h
e_padlock.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
e_padlock.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
e_padlock.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
e_padlock.o: ../include/openssl/safestack.h ../include/openssl/sha.h
e_padlock.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
e_padlock.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
e_padlock.o: e_padlock.c
