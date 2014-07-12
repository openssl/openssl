#
# OpenSSL/fips/utl/Makefile
#

DIR_fips_utl=	utl
INCLUDES_fips_utl=

CFLAGS_fips_utl= $(INCLUDES_fips_utl) $(CFLAG)

GENERAL_fips_utl=Makefile
TEST_fips_utl=
APPS_fips_utl=

LIB_fips_utl=$(TOP_fips_utl)/libcrypto.a
LIBSRC_fips_utl= fips_err.c fips_md.c fips_enc.c fips_lck.c fips_mem.c
LIBOBJ_fips_utl= fips_err.o fips_md.o fips_enc.o fips_lck.o fips_mem.o

SRC_fips_utl= $(LIBSRC_fips_utl)

EXHEADER_fips_utl=
HEADER_fips_utl=	$(EXHEADER_fips_utl)

ALL_fips_utl=    $(GENERAL_fips_utl) $(SRC_fips_utl) $(HEADER_fips_utl)

top: top_fips_utl
top_fips_utl:
	(cd $(TOP_fips_utl); $(MAKE) DIRS=fips FDIRS=$(DIR_fips_utl) sub_all)

all: all_fips_utl
all_fips_utl:	lib

lib:	$(LIBOBJ_fips_utl)
	@echo $(LIBOBJ_fips_utl) > lib

files: files_fips_utl
files_fips_utl:
	$(PERL) $(TOP_fips_utl)/util/files.pl TOP=$(TOP_fips_utl) Makefile >> $(TOP_fips_utl)/MINFO

links: links_fips_utl
links_fips_utl:
	@$(PERL) $(TOP_fips_utl)/util/mklink.pl $(TOP_fips_utl)/include/openssl $(EXHEADER_fips_utl)
	@$(PERL) $(TOP_fips_utl)/util/mklink.pl $(TOP_fips_utl)/test $(TEST_fips_utl)
	@$(PERL) $(TOP_fips_utl)/util/mklink.pl $(TOP_fips_utl)/apps $(APPS_fips_utl)

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
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_utl
clean_fips_utl:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_fips_utl) $(CPPFLAGS) -c -o $@ $<
