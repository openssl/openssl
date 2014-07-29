#
# crypto/ec/Makefile
#

INCLUDES_crypto_ec= -Icrypto -I. -Iinclude

CFLAGS_crypto_ec= $(INCLUDES_crypto_ec) $(CFLAG)
ASFLAGS_crypto_ec= $(INCLUDES_crypto_ec) $(ASFLAG)
AFLAGS_crypto_ec= $(ASFLAGS_crypto_ec)

GENERAL_crypto_ec=crypto/ec/Makefile
TEST_crypto_ec=crypto/ec/ectest.c
APPS_crypto_ec=

LIB_crypto_ec=libcrypto.a
LIBSRC_crypto_ec=	crypto/ec/ec_lib.c crypto/ec/ecp_smpl.c crypto/ec/ecp_mont.c crypto/ec/ecp_nist.c crypto/ec/ec_cvt.c crypto/ec/ec_mult.c\
	crypto/ec/ec_err.c crypto/ec/ec_curve.c crypto/ec/ec_check.c crypto/ec/ec_print.c crypto/ec/ec_asn1.c crypto/ec/ec_key.c\
	crypto/ec/ec2_smpl.c crypto/ec/ec2_mult.c crypto/ec/ec_ameth.c crypto/ec/ec_pmeth.c crypto/ec/eck_prn.c \
	crypto/ec/ecp_nistp224.c crypto/ec/ecp_nistp256.c crypto/ec/ecp_nistp521.c crypto/ec/ecp_nistputil.c \
	crypto/ec/ecp_oct.c crypto/ec/ec2_oct.c crypto/ec/ec_oct.c

LIBOBJ_crypto_ec=	crypto/ec/ec_lib.o crypto/ec/ecp_smpl.o crypto/ec/ecp_mont.o crypto/ec/ecp_nist.o crypto/ec/ec_cvt.o crypto/ec/ec_mult.o\
	crypto/ec/ec_err.o crypto/ec/ec_curve.o crypto/ec/ec_check.o crypto/ec/ec_print.o crypto/ec/ec_asn1.o crypto/ec/ec_key.o\
	crypto/ec/ec2_smpl.o crypto/ec/ec2_mult.o crypto/ec/ec_ameth.o crypto/ec/ec_pmeth.o crypto/ec/eck_prn.o \
	crypto/ec/ecp_nistp224.o crypto/ec/ecp_nistp256.o crypto/ec/ecp_nistp521.o crypto/ec/ecp_nistputil.o \
	crypto/ec/ecp_oct.o crypto/ec/ec2_oct.o crypto/ec/ec_oct.o $(EC_ASM)

SRC_crypto_ec= $(LIBSRC_crypto_ec)

EXHEADER_crypto_ec= crypto/ec/ec.h
HEADER_crypto_ec=	crypto/ec/ec_lcl.h $(EXHEADER_crypto_ec)

ALL_crypto_ec=    $(GENERAL_crypto_ec) $(SRC_crypto_ec) $(HEADER_crypto_ec)


all: all_crypto_ec
all_crypto_ec:	crypto/ec/lib

crypto/ec/lib:	$(LIBOBJ_crypto_ec)
	$(ARX) $(LIB_crypto_ec) $(LIBOBJ_crypto_ec)
	$(RANLIB) $(LIB_crypto_ec) || echo Never mind.
	@touch crypto/ec/lib

files: files_crypto_ec
files_crypto_ec:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ec
links_crypto_ec:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ec)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ec)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ec)

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
	lint -DLINT $(INCLUDES_crypto_ec) $(SRC_crypto_ec)>crypto/ec/fluff

dclean: dclean_crypto_ec
dclean_crypto_ec:

clean: clean_crypto_ec
clean_crypto_ec:
	rm -f crypto/ec/*.o crypto/ec/*.d */*.o */*.d crypto/ec/*.obj crypto/ec/lib crypto/ec/tags crypto/ec/core crypto/ec/.pure crypto/ec/.nfs* crypto/ec/*.old crypto/ec/*.bak crypto/ec/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_ec) $(CPPFLAGS) -c -o $@ $<
.s.o:
	$(AS) $(ASFLAGS_crypto_ec) -o $@ $<
