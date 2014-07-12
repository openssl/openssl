#
# OpenSSL/fips/sha/Makefile
#

DIR=	sha
INCLUDES=

ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= fips_shatest.c
APPS=
EXE= fips_standalone_sha1$(EXE_EXT)

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_sha1_selftest.c
LIBOBJ=fips_sha1_selftest.o

SRC= $(LIBSRC)
PROGS= fips_standalone_sha1.c

EXHEADER=
HEADER=	

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_sha
top_fips_sha:
	(cd $(TOP); $(MAKE) DIRS=fips SDIRS=$(DIR) sub_all)

all: all_fips_sha
all_fips_sha:	../fips_standalone_sha1$(EXE_EXT) lib

lib: lib_fips_sha
lib_fips_sha:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

../fips_standalone_sha1$(EXE_EXT): fips_standalone_sha1.o
	if [ -z "$(HOSTCC)" ] ; then \
	FIPS_SHA_ASM=""; for i in $(SHA1_ASM_OBJ) sha1dgst.o ; do FIPS_SHA_ASM="$$FIPS_SHA_ASM ../../crypto/sha/$$i" ; done; \
	$(CC) -o $@ $(CFLAGS) fips_standalone_sha1.o $$FIPS_SHA_ASM ; \
	else \
		$(HOSTCC) $(HOSTCFLAGS) -o $ $@ -I../../include -I../../crypto fips_standalone_sha1.c ../../crypto/sha/sha1dgst.c ; \
	fi

files: files_fips_sha
files_fips_sha:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_sha
links_fips_sha:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_sha
install_fips_sha:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_sha
tags_fips_sha:
	ctags $(SRC)

tests: tests_fips_sha
tests_fips_sha:

Q=../testvectors/sha/req
A=../testvectors/sha/rsp

VECTORS = SHA1LongMsg \
	SHA1Monte \
	SHA1ShortMsg \
	SHA224LongMsg \
	SHA224Monte \
	SHA224ShortMsg \
	SHA256LongMsg \
	SHA256Monte \
	SHA256ShortMsg \
	SHA384LongMsg \
	SHA384Monte \
	SHA384ShortMsg \
	SHA512LongMsg \
	SHA512Monte \
	SHA512ShortMsg

fips_test: fips_test_fips_sha
fips_test_fips_sha:
	-rm -rf $(A)
	mkdir $(A)
	for file in $(VECTORS); do \
	    if [ -f $(Q)/$$file.req ]; then \
		$(TOP)/util/shlib_wrap.sh $(TOP)/test/fips_shatest $(Q)/$$file.req $(A)/$$file.rsp; \
	    fi; \
	done

lint: lint_fips_sha
lint_fips_sha:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean: dclean_fips_sha
dclean_fips_sha:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_sha
clean_fips_sha:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE)

