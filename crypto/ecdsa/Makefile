#
# crypto/ecdsa/Makefile
#

DIR_crypto_ecdsa=	ecdsa
INCLUDES_crypto_ecdsa= -I.. -I$(TOP_crypto_ecdsa) -I../../include

CFLAGS_crypto_ecdsa= $(INCLUDES_crypto_ecdsa) $(CFLAG)

GENERAL_crypto_ecdsa=Makefile
TEST_crypto_ecdsa=ecdsatest.c
APPS_crypto_ecdsa=

LIB_crypto_ecdsa=$(TOP_crypto_ecdsa)/libcrypto.a
LIBSRC_crypto_ecdsa=	ecs_lib.c ecs_asn1.c ecs_ossl.c ecs_sign.c ecs_vrf.c ecs_err.c

LIBOBJ_crypto_ecdsa=	ecs_lib.o ecs_asn1.o ecs_ossl.o ecs_sign.o ecs_vrf.o ecs_err.o

SRC_crypto_ecdsa= $(LIBSRC_crypto_ecdsa)

EXHEADER_crypto_ecdsa= ecdsa.h
HEADER_crypto_ecdsa=	ecs_locl.h $(EXHEADER_crypto_ecdsa)

ALL_crypto_ecdsa=    $(GENERAL_crypto_ecdsa) $(SRC_crypto_ecdsa) $(HEADER_crypto_ecdsa)

top: top_crypto_ecdsa
top_crypto_ecdsa:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_ecdsa) sub_all)

all: all_crypto_ecdsa
all_crypto_ecdsa:	lib

lib:	$(LIBOBJ_crypto_ecdsa)
	$(ARX) $(LIB_crypto_ecdsa) $(LIBOBJ_crypto_ecdsa)
	$(RANLIB) $(LIB_crypto_ecdsa) || echo Never mind.
	@touch lib

files: files_crypto_ecdsa
files_crypto_ecdsa:
	$(PERL) $(TOP_crypto_ecdsa)/util/files.pl TOP=$(TOP_crypto_ecdsa) Makefile >> $(TOP_crypto_ecdsa)/MINFO

links: links_crypto_ecdsa
links_crypto_ecdsa:
	@$(PERL) $(TOP_crypto_ecdsa)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ecdsa)
	@$(PERL) $(TOP_crypto_ecdsa)/util/mklink.pl ../../test $(TEST_crypto_ecdsa)
	@$(PERL) $(TOP_crypto_ecdsa)/util/mklink.pl ../../apps $(APPS_crypto_ecdsa)

install: install_crypto_ecdsa
install_crypto_ecdsa:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ecdsa)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ecdsa
tags_crypto_ecdsa:
	ctags $(SRC_crypto_ecdsa)

tests: tests_crypto_ecdsa
tests_crypto_ecdsa:

lint: lint_crypto_ecdsa
lint_crypto_ecdsa:
	lint -DLINT $(INCLUDES_crypto_ecdsa) $(SRC_crypto_ecdsa)>fluff

dclean: dclean_crypto_ecdsa
dclean_crypto_ecdsa:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_ecdsa
clean_crypto_ecdsa:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_ecdsa) $(CPPFLAGS) -c -o $@ $<
