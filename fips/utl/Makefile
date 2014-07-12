#
# OpenSSL/fips/utl/Makefile
#

DIR=	utl
INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= fips_err.c fips_md.c fips_enc.c fips_lck.c fips_mem.c
LIBOBJ= fips_err.o fips_md.o fips_enc.o fips_lck.o fips_mem.o

SRC= $(LIBSRC)

EXHEADER=
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top: top_fips_utl
top_fips_utl:
	(cd $(TOP); $(MAKE) DIRS=fips FDIRS=$(DIR) sub_all)

all: all_fips_utl
all_fips_utl:	lib

lib: lib_fips_utl
lib_fips_utl:	$(LIBOBJ)
	@echo $(LIBOBJ) > lib

files: files_fips_utl
files_fips_utl:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_fips_utl
links_fips_utl:
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl $(TOP)/apps $(APPS)

install: install_fips_utl
install_fips_utl:
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	  (cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	  chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done

tags: tags_fips_utl
tags_fips_utl:
	ctags $(SRC)

tests: tests_fips_utl
tests_fips_utl:

dclean: dclean_fips_utl
dclean_fips_utl:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_fips_utl
clean_fips_utl:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
