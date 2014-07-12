#
# OpenSSL/fips/sha/Makefile
#

DIR_fips_sha=	sha
INCLUDES_fips_sha=

ASFLAGS_fips_sha= $(INCLUDES_fips_sha) $(ASFLAG)
AFLAGS_fips_sha= $(ASFLAGS_fips_sha)

CFLAGS_fips_sha= $(INCLUDES_fips_sha) $(CFLAG)

GENERAL_fips_sha=Makefile
TEST_fips_sha= fips_shatest.c
APPS_fips_sha=
EXE_fips_sha= fips_standalone_sha1$(EXE_EXT)

LIB_fips_sha=$(TOP_fips_sha)/libcrypto.a
LIBSRC_fips_sha=fips_sha1_selftest.c
LIBOBJ_fips_sha=fips_sha1_selftest.o

SRC_fips_sha= $(LIBSRC_fips_sha)
PROGS_fips_sha= fips_standalone_sha1.c

EXHEADER_fips_sha=
HEADER_fips_sha=	

ALL_fips_sha=    $(GENERAL_fips_sha) $(SRC_fips_sha) $(HEADER_fips_sha)

top: top_fips_sha
top_fips_sha:
	(cd $(TOP_fips_sha); $(MAKE) DIRS=fips SDIRS=$(DIR_fips_sha) sub_all)

all: all_fips_sha
all_fips_sha:	../fips_standalone_sha1$(EXE_EXT) lib

lib:	$(LIBOBJ_fips_sha)
	@echo $(LIBOBJ_fips_sha) > lib

../fips_standalone_sha1$(EXE_EXT): fips_standalone_sha1.o
	if [ -z "$(HOSTCC)" ] ; then \
	FIPS_SHA_ASM=""; for i in $(SHA1_ASM_OBJ) sha1dgst.o ; do FIPS_SHA_ASM="$$FIPS_SHA_ASM ../../crypto/sha/$$i" ; done; \
	$(CC) -o $@ $(CFLAGS_fips_sha) fips_standalone_sha1.o $$FIPS_SHA_ASM ; \
	else \
		$(HOSTCC) $(HOSTCFLAGS) -o $ $@ -I../../include -I../../crypto fips_standalone_sha1.c ../../crypto/sha/sha1dgst.c ; \
	fi

files: files_fips_sha
files_fips_sha:
	$(PERL) $(TOP_fips_sha)/util/files.pl TOP=$(TOP_fips_sha) Makefile >> $(TOP_fips_sha)/MINFO

links: links_fips_sha
links_fips_sha:
	@$(PERL) $(TOP_fips_sha)/util/mklink.pl $(TOP_fips_sha)/include/openssl $(EXHEADER_fips_sha)
	@$(PERL) $(TOP_fips_sha)/util/mklink.pl $(TOP_fips_sha)/test $(TEST_fips_sha)
	@$(PERL) $(TOP_fips_sha)/util/mklink.pl $(TOP_fips_sha)/apps $(APPS_fips_sha)

install: install_fips_sha
install_fips_sha:
	@headerlist="$(EXHEADER_fips_sha)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_sha
tags_fips_sha:
	ctags $(SRC_fips_sha)

tests: tests_fips_sha
tests_fips_sha:

Q_fips_sha=../testvectors/sha/req
A_fips_sha=../testvectors/sha/rsp

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
	-rm -rf $(A_fips_sha)
	mkdir $(A_fips_sha)
	for file in $(VECTORS); do \
	    if [ -f $(Q_fips_sha)/$$file.req ]; then \
		$(TOP_fips_sha)/util/shlib_wrap.sh $(TOP_fips_sha)/test/fips_shatest $(Q_fips_sha)/$$file.req $(A_fips_sha)/$$file.rsp; \
	    fi; \
	done

lint: lint_fips_sha
lint_fips_sha:
	lint -DLINT $(INCLUDES_fips_sha) $(SRC_fips_sha)>fluff

dclean: dclean_fips_sha
dclean_fips_sha:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_sha
clean_fips_sha:
	rm -f *.o *.d asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(EXE_fips_sha)

.c.o:
	$(CC) $(CFLAGS_fips_sha) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips_sha) -o $@ $<
