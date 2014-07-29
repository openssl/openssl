#
# OpenSSL/fips/sha/Makefile
#

INCLUDES_fips_sha=

ASFLAGS_fips_sha= $(INCLUDES_fips_sha) $(ASFLAG)
AFLAGS_fips_sha= $(ASFLAGS_fips_sha)

CFLAGS_fips_sha= $(INCLUDES_fips_sha) $(CFLAG)

GENERAL_fips_sha=fips/sha/Makefile
TEST_fips_sha= fips/sha/fips_shatest.c
APPS_fips_sha=
EXE_fips_sha= fips/sha/fips_standalone_sha1$(EXE_EXT)

LIB_fips_sha=libcrypto.a
LIBSRC_fips_sha=fips/sha/fips_sha1_selftest.c
LIBOBJ_fips_sha=fips/sha/fips_sha1_selftest.o

SRC_fips_sha= $(LIBSRC_fips_sha)
PROGS_fips_sha= fips_standalone_sha1.c

EXHEADER_fips_sha=
HEADER_fips_sha=	

ALL_fips_sha=    $(GENERAL_fips_sha) $(SRC_fips_sha) $(HEADER_fips_sha)


all: all_fips_sha
all_fips_sha:	fips/fips_standalone_sha1$(EXE_EXT) fips/sha/lib

fips/sha/lib:	$(LIBOBJ_fips_sha)
	@echo $(LIBOBJ_fips_sha) > fips/sha/lib

files: files_fips_sha
files_fips_sha:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_sha
links_fips_sha:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_sha)
	@$(PERL) util/mklink.pl test $(TEST_fips_sha)
	@$(PERL) util/mklink.pl apps $(APPS_fips_sha)

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
		util/shlib_wrap.sh test/fips_shatest $(Q_fips_sha)/$$file.req $(A_fips_sha)/$$file.rsp; \
	    fi; \
	done

lint: lint_fips_sha
lint_fips_sha:
	lint -DLINT $(INCLUDES_fips_sha) $(SRC_fips_sha)>fips/sha/fluff

dclean: dclean_fips_sha
dclean_fips_sha:

clean: clean_fips_sha
clean_fips_sha:
	rm -f fips/sha/*.o fips/sha/*.d asm/*.o fips/sha/*.obj fips/sha/lib fips/sha/tags fips/sha/core fips/sha/.pure fips/sha/.nfs* fips/sha/*.old fips/sha/*.bak fips/sha/fluff $(EXE_fips_sha)

.c.o:
	$(CC) $(CFLAGS_fips_sha) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_fips_sha) -o $@ $<
