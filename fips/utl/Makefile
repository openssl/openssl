#
# OpenSSL/fips/utl/Makefile
#

INCLUDES_fips_utl=

CFLAGS_fips_utl= $(INCLUDES_fips_utl) $(CFLAG)

GENERAL_fips_utl=fips/utl/Makefile
TEST_fips_utl=
APPS_fips_utl=

LIB_fips_utl=libcrypto.a
LIBSRC_fips_utl= fips/utl/fips_err.c fips/utl/fips_md.c fips/utl/fips_enc.c fips/utl/fips_lck.c fips/utl/fips_mem.c
LIBOBJ_fips_utl= fips/utl/fips_err.o fips/utl/fips_md.o fips/utl/fips_enc.o fips/utl/fips_lck.o fips/utl/fips_mem.o

SRC_fips_utl= $(LIBSRC_fips_utl)

EXHEADER_fips_utl=
HEADER_fips_utl=	$(EXHEADER_fips_utl)

ALL_fips_utl=    $(GENERAL_fips_utl) $(SRC_fips_utl) $(HEADER_fips_utl)


all: all_fips_utl
all_fips_utl:	fips/utl/lib

fips/utl/lib:	$(LIBOBJ_fips_utl)
	@echo $(LIBOBJ_fips_utl) > fips/utl/lib

files: files_fips_utl
files_fips_utl:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_fips_utl
links_fips_utl:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_fips_utl)
	@$(PERL) util/mklink.pl test $(TEST_fips_utl)
	@$(PERL) util/mklink.pl apps $(APPS_fips_utl)

install: install_fips_utl
install_fips_utl:
	@headerlist="$(EXHEADER_fips_utl)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_utl
tags_fips_utl:
	ctags $(SRC_fips_utl)

tests: tests_fips_utl
tests_fips_utl:

dclean: dclean_fips_utl
dclean_fips_utl:

clean: clean_fips_utl
clean_fips_utl:
	rm -f fips/utl/*.o fips/utl/*.d fips/utl/*.obj fips/utl/lib fips/utl/tags fips/utl/core fips/utl/.pure fips/utl/.nfs* fips/utl/*.old fips/utl/*.bak fips/utl/fluff

.c.o:
	$(CC) $(CFLAGS_fips_utl) $(CPPFLAGS) -c -o $@ $<
