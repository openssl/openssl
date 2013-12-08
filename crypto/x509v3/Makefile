#
# OpenSSL/crypto/x509v3/Makefile
#

DIR=	x509v3
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	v3_bcons.c v3_bitst.c v3_conf.c v3_extku.c v3_ia5.c v3_lib.c \
v3_prn.c v3_utl.c v3err.c v3_genn.c v3_alt.c v3_skey.c v3_akey.c v3_pku.c \
v3_int.c v3_enum.c v3_sxnet.c v3_cpols.c v3_crld.c v3_purp.c v3_info.c \
v3_ocsp.c v3_akeya.c v3_pmaps.c v3_pcons.c v3_ncons.c v3_pcia.c v3_pci.c \
pcy_cache.c pcy_node.c pcy_data.c pcy_map.c pcy_tree.c pcy_lib.c \
v3_asid.c v3_addr.c
LIBOBJ= v3_bcons.o v3_bitst.o v3_conf.o v3_extku.o v3_ia5.o v3_lib.o \
v3_prn.o v3_utl.o v3err.o v3_genn.o v3_alt.o v3_skey.o v3_akey.o v3_pku.o \
v3_int.o v3_enum.o v3_sxnet.o v3_cpols.o v3_crld.o v3_purp.o v3_info.o \
v3_ocsp.o v3_akeya.o v3_pmaps.o v3_pcons.o v3_ncons.o v3_pcia.o v3_pci.o \
pcy_cache.o pcy_node.o pcy_data.o pcy_map.o pcy_tree.o pcy_lib.o \
v3_asid.o v3_addr.o

SRC= $(LIBSRC)

EXHEADER= x509v3.h
HEADER=	$(EXHEADER) pcy_int.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

pcy_cache.o: ../../e_os.h ../../include/openssl/asn1.h
pcy_cache.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
pcy_cache.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pcy_cache.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pcy_cache.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pcy_cache.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pcy_cache.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pcy_cache.o: ../cryptlib.h pcy_cache.c pcy_int.h
pcy_data.o: ../../e_os.h ../../include/openssl/asn1.h
pcy_data.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
pcy_data.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pcy_data.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pcy_data.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pcy_data.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pcy_data.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pcy_data.o: ../cryptlib.h pcy_data.c pcy_int.h
pcy_lib.o: ../../e_os.h ../../include/openssl/asn1.h
pcy_lib.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
pcy_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pcy_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pcy_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pcy_lib.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pcy_lib.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pcy_lib.o: ../cryptlib.h pcy_int.h pcy_lib.c
pcy_map.o: ../../e_os.h ../../include/openssl/asn1.h
pcy_map.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
pcy_map.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pcy_map.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pcy_map.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pcy_map.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pcy_map.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pcy_map.o: ../cryptlib.h pcy_int.h pcy_map.c
pcy_node.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pcy_node.o: ../../include/openssl/conf.h ../../include/openssl/lhash.h
pcy_node.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pcy_node.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pcy_node.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pcy_node.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pcy_node.o: pcy_int.h pcy_node.c
pcy_tree.o: ../../e_os.h ../../include/openssl/asn1.h
pcy_tree.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
pcy_tree.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pcy_tree.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
pcy_tree.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
pcy_tree.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
pcy_tree.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
pcy_tree.o: ../cryptlib.h pcy_int.h pcy_tree.c
v3_addr.o: ../../e_os.h ../../include/openssl/asn1.h
v3_addr.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_addr.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_addr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_addr.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_addr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_addr.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_addr.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_addr.c
v3_akey.o: ../../e_os.h ../../include/openssl/asn1.h
v3_akey.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_akey.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_akey.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_akey.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_akey.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_akey.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_akey.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_akey.c
v3_akeya.o: ../../e_os.h ../../include/openssl/asn1.h
v3_akeya.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_akeya.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_akeya.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_akeya.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_akeya.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_akeya.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_akeya.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_akeya.c
v3_alt.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_alt.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_alt.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_alt.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_alt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_alt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_alt.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_alt.c
v3_asid.o: ../../e_os.h ../../include/openssl/asn1.h
v3_asid.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_asid.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_asid.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_asid.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_asid.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_asid.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_asid.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_asid.c
v3_bcons.o: ../../e_os.h ../../include/openssl/asn1.h
v3_bcons.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_bcons.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_bcons.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_bcons.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_bcons.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_bcons.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_bcons.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_bcons.c
v3_bitst.o: ../../e_os.h ../../include/openssl/asn1.h
v3_bitst.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_bitst.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
v3_bitst.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
v3_bitst.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
v3_bitst.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
v3_bitst.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
v3_bitst.o: ../cryptlib.h v3_bitst.c
v3_conf.o: ../../e_os.h ../../include/openssl/asn1.h
v3_conf.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_conf.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
v3_conf.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
v3_conf.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
v3_conf.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
v3_conf.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
v3_conf.o: ../cryptlib.h v3_conf.c
v3_cpols.o: ../../e_os.h ../../include/openssl/asn1.h
v3_cpols.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_cpols.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_cpols.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_cpols.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_cpols.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_cpols.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_cpols.o: ../../include/openssl/x509v3.h ../cryptlib.h pcy_int.h v3_cpols.c
v3_crld.o: ../../e_os.h ../../include/openssl/asn1.h
v3_crld.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_crld.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_crld.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_crld.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_crld.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_crld.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_crld.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_crld.c
v3_enum.o: ../../e_os.h ../../include/openssl/asn1.h
v3_enum.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_enum.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
v3_enum.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
v3_enum.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
v3_enum.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
v3_enum.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
v3_enum.o: ../cryptlib.h v3_enum.c
v3_extku.o: ../../e_os.h ../../include/openssl/asn1.h
v3_extku.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_extku.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_extku.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_extku.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_extku.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_extku.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_extku.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_extku.c
v3_genn.o: ../../e_os.h ../../include/openssl/asn1.h
v3_genn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_genn.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_genn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_genn.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_genn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_genn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_genn.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_genn.c
v3_ia5.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_ia5.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_ia5.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_ia5.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_ia5.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_ia5.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_ia5.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_ia5.c
v3_info.o: ../../e_os.h ../../include/openssl/asn1.h
v3_info.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_info.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_info.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_info.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_info.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_info.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_info.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_info.c
v3_int.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_int.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_int.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_int.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_int.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_int.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_int.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_int.c
v3_lib.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_lib.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_lib.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_lib.o: ../../include/openssl/x509v3.h ../cryptlib.h ext_dat.h v3_lib.c
v3_ncons.o: ../../e_os.h ../../include/openssl/asn1.h
v3_ncons.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_ncons.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_ncons.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_ncons.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_ncons.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_ncons.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_ncons.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_ncons.c
v3_ocsp.o: ../../e_os.h ../../include/openssl/asn1.h
v3_ocsp.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_ocsp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
v3_ocsp.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
v3_ocsp.o: ../../include/openssl/ocsp.h ../../include/openssl/pkcs7.h
v3_ocsp.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_ocsp.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_ocsp.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_ocsp.c
v3_pci.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_pci.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_pci.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_pci.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_pci.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_pci.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_pci.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_pci.c
v3_pcia.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
v3_pcia.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_pcia.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_pcia.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_pcia.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_pcia.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_pcia.o: ../../include/openssl/x509v3.h v3_pcia.c
v3_pcons.o: ../../e_os.h ../../include/openssl/asn1.h
v3_pcons.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_pcons.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_pcons.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_pcons.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_pcons.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_pcons.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_pcons.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_pcons.c
v3_pku.o: ../../e_os.h ../../include/openssl/asn1.h
v3_pku.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_pku.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_pku.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_pku.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_pku.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_pku.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_pku.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_pku.c
v3_pmaps.o: ../../e_os.h ../../include/openssl/asn1.h
v3_pmaps.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_pmaps.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_pmaps.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_pmaps.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_pmaps.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_pmaps.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_pmaps.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_pmaps.c
v3_prn.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_prn.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_prn.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_prn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_prn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_prn.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_prn.c
v3_purp.o: ../../e_os.h ../../include/openssl/asn1.h
v3_purp.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_purp.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
v3_purp.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
v3_purp.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
v3_purp.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
v3_purp.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
v3_purp.o: ../cryptlib.h v3_purp.c
v3_skey.o: ../../e_os.h ../../include/openssl/asn1.h
v3_skey.o: ../../include/openssl/bio.h ../../include/openssl/conf.h
v3_skey.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
v3_skey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
v3_skey.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
v3_skey.o: ../../include/openssl/stack.h ../../include/openssl/x509.h
v3_skey.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
v3_skey.o: ../cryptlib.h v3_skey.c
v3_sxnet.o: ../../e_os.h ../../include/openssl/asn1.h
v3_sxnet.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
v3_sxnet.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_sxnet.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_sxnet.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_sxnet.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_sxnet.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_sxnet.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_sxnet.c
v3_utl.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3_utl.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3_utl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3_utl.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3_utl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3_utl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3_utl.o: ../../include/openssl/x509v3.h ../cryptlib.h v3_utl.c
v3err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
v3err.o: ../../include/openssl/conf.h ../../include/openssl/err.h
v3err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
v3err.o: ../../include/openssl/objects.h ../../include/openssl/pkcs7.h
v3err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
v3err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
v3err.o: ../../include/openssl/x509v3.h v3err.c
