#
# crypto/ec/Makefile
#

DIR_crypto_ec=	ec
INCLUDES_crypto_ec= -I.. -I$(TOP_crypto_ec) -I../../include

CFLAGS_crypto_ec= $(INCLUDES_crypto_ec) $(CFLAG)
ASFLAGS_crypto_ec= $(INCLUDES_crypto_ec) $(ASFLAG)
AFLAGS_crypto_ec= $(ASFLAGS_crypto_ec)

GENERAL_crypto_ec=Makefile
TEST_crypto_ec=ectest.c
APPS_crypto_ec=

LIB_crypto_ec=$(TOP_crypto_ec)/libcrypto.a
LIBSRC_crypto_ec=	ec_lib.c ecp_smpl.c ecp_mont.c ecp_nist.c ec_cvt.c ec_mult.c\
	ec_err.c ec_curve.c ec_check.c ec_print.c ec_asn1.c ec_key.c\
	ec2_smpl.c ec2_mult.c ec_ameth.c ec_pmeth.c eck_prn.c \
	ecp_nistp224.c ecp_nistp256.c ecp_nistp521.c ecp_nistputil.c \
	ecp_oct.c ec2_oct.c ec_oct.c

LIBOBJ_crypto_ec=	ec_lib.o ecp_smpl.o ecp_mont.o ecp_nist.o ec_cvt.o ec_mult.o\
	ec_err.o ec_curve.o ec_check.o ec_print.o ec_asn1.o ec_key.o\
	ec2_smpl.o ec2_mult.o ec_ameth.o ec_pmeth.o eck_prn.o \
	ecp_nistp224.o ecp_nistp256.o ecp_nistp521.o ecp_nistputil.o \
	ecp_oct.o ec2_oct.o ec_oct.o $(EC_ASM)

SRC_crypto_ec= $(LIBSRC_crypto_ec)

EXHEADER_crypto_ec= ec.h
HEADER_crypto_ec=	ec_lcl.h $(EXHEADER_crypto_ec)

ALL_crypto_ec=    $(GENERAL_crypto_ec) $(SRC_crypto_ec) $(HEADER_crypto_ec)

top: top_crypto_ec
top_crypto_ec:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_ec) sub_all)

all: all_crypto_ec
all_crypto_ec:	lib

lib: lib_crypto_ec
lib_crypto_ec:	$(LIBOBJ_crypto_ec)
	$(ARX) $(LIB_crypto_ec) $(LIBOBJ_crypto_ec)
	$(RANLIB) $(LIB_crypto_ec) || echo Never mind.
	@touch lib

files: files_crypto_ec
files_crypto_ec:
	$(PERL) $(TOP_crypto_ec)/util/files.pl TOP=$(TOP_crypto_ec) Makefile >> $(TOP_crypto_ec)/MINFO

links: links_crypto_ec
links_crypto_ec:
	@$(PERL) $(TOP_crypto_ec)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ec)
	@$(PERL) $(TOP_crypto_ec)/util/mklink.pl ../../test $(TEST_crypto_ec)
	@$(PERL) $(TOP_crypto_ec)/util/mklink.pl ../../apps $(APPS_crypto_ec)

install: install_crypto_ec
install_crypto_ec:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ec)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ec
tags_crypto_ec:
	ctags $(SRC_crypto_ec)

tests: tests_crypto_ec
tests_crypto_ec:

lint: lint_crypto_ec
lint_crypto_ec:
	lint -DLINT $(INCLUDES_crypto_ec) $(SRC_crypto_ec)>fluff

dclean: dclean_crypto_ec
dclean_crypto_ec:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_ec
clean_crypto_ec:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_ec) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_ec) -o $@ $<
