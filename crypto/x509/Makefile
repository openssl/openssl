#
# OpenSSL/crypto/x509/Makefile
#

DIR=	x509
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README

LIB=$(TOP)/libcrypto.a
LIBSRC=	x509_def.c x509_d2.c x509_r2x.c x509_cmp.c \
	x509_obj.c x509_req.c x509spki.c x509_vfy.c \
	x509_set.c x509cset.c x509rset.c x509_err.c \
	x509name.c x509_v3.c x509_ext.c x509_att.c \
	x509type.c x509_lu.c x_all.c x509_txt.c \
	x509_trs.c by_file.c by_dir.c x509_vpm.c \
	x_crl.c t_crl.c x_req.c t_req.c x_x509.c t_x509.c \
	x_x509a.c x_attrib.c x_exten.c x_name.c
LIBOBJ= x509_def.o x509_d2.o x509_r2x.o x509_cmp.o \
	x509_obj.o x509_req.o x509spki.o x509_vfy.o \
	x509_set.o x509cset.o x509rset.o x509_err.o \
	x509name.o x509_v3.o x509_ext.o x509_att.o \
	x509type.o x509_lu.o x_all.o x509_txt.o \
	x509_trs.o by_file.o by_dir.o x509_vpm.o \
	x_crl.o t_crl.o x_req.o t_req.o x_x509.o t_x509.o \
	x_x509a.o x_attrib.o x_exten.o x_name.o

SRC= $(LIBSRC)

HEADER=	x509_lcl.h

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

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

by_dir.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
by_dir.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
by_dir.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
by_dir.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
by_dir.o: ../../include/openssl/err.h ../../include/openssl/evp.h
by_dir.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
by_dir.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
by_dir.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
by_dir.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
by_dir.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
by_dir.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
by_dir.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
by_dir.o: ../include/internal/x509_int.h by_dir.c
by_file.o: ../../e_os.h ../../include/openssl/asn1.h
by_file.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
by_file.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
by_file.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
by_file.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
by_file.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
by_file.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
by_file.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
by_file.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
by_file.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
by_file.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
by_file.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
by_file.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
by_file.o: ../include/internal/cryptlib.h by_file.c
t_crl.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_crl.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
t_crl.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
t_crl.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
t_crl.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
t_crl.o: ../../include/openssl/err.h ../../include/openssl/evp.h
t_crl.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_crl.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
t_crl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
t_crl.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
t_crl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
t_crl.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
t_crl.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
t_crl.o: ../include/internal/cryptlib.h t_crl.c
t_req.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_req.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
t_req.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
t_req.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
t_req.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
t_req.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
t_req.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
t_req.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
t_req.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
t_req.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
t_req.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
t_req.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
t_req.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
t_req.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
t_req.o: ../include/internal/cryptlib.h t_req.c
t_x509.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
t_x509.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
t_x509.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
t_x509.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
t_x509.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
t_x509.o: ../../include/openssl/err.h ../../include/openssl/evp.h
t_x509.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
t_x509.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
t_x509.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
t_x509.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
t_x509.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
t_x509.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
t_x509.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
t_x509.o: ../include/internal/asn1_int.h ../include/internal/cryptlib.h
t_x509.o: t_x509.c
x509_att.o: ../../e_os.h ../../include/openssl/asn1.h
x509_att.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_att.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_att.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_att.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_att.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_att.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_att.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_att.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_att.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_att.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_att.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_att.o: ../include/internal/cryptlib.h x509_att.c x509_lcl.h
x509_cmp.o: ../../e_os.h ../../include/openssl/asn1.h
x509_cmp.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_cmp.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_cmp.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_cmp.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_cmp.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_cmp.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_cmp.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_cmp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_cmp.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_cmp.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_cmp.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_cmp.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_cmp.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h
x509_cmp.o: x509_cmp.c
x509_d2.o: ../../e_os.h ../../include/openssl/asn1.h
x509_d2.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_d2.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_d2.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_d2.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_d2.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_d2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_d2.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x509_d2.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x509_d2.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_d2.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_d2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_d2.o: ../include/internal/cryptlib.h x509_d2.c
x509_def.o: ../../e_os.h ../../include/openssl/asn1.h
x509_def.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_def.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_def.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_def.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_def.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_def.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_def.o: ../../include/openssl/opensslconf.h
x509_def.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_def.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_def.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_def.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_def.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509_def.o: x509_def.c
x509_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_err.o: ../../include/openssl/x509_vfy.h x509_err.c
x509_ext.o: ../../e_os.h ../../include/openssl/asn1.h
x509_ext.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_ext.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_ext.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_ext.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_ext.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_ext.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_ext.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_ext.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_ext.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_ext.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_ext.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_ext.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_ext.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h
x509_ext.o: x509_ext.c
x509_lu.o: ../../e_os.h ../../include/openssl/asn1.h
x509_lu.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_lu.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_lu.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_lu.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_lu.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_lu.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_lu.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_lu.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_lu.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_lu.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_lu.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_lu.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_lu.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h
x509_lu.o: x509_lcl.h x509_lu.c
x509_obj.o: ../../e_os.h ../../include/openssl/asn1.h
x509_obj.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_obj.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_obj.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_obj.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_obj.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_obj.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_obj.o: ../../include/openssl/opensslconf.h
x509_obj.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_obj.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_obj.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_obj.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_obj.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509_obj.o: ../include/internal/x509_int.h x509_obj.c
x509_r2x.o: ../../e_os.h ../../include/openssl/asn1.h
x509_r2x.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
x509_r2x.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_r2x.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_r2x.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_r2x.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_r2x.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_r2x.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_r2x.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_r2x.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_r2x.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_r2x.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_r2x.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509_r2x.o: ../include/internal/x509_int.h x509_r2x.c
x509_req.o: ../../e_os.h ../../include/openssl/asn1.h
x509_req.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x509_req.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x509_req.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_req.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_req.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_req.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_req.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_req.o: ../../include/openssl/opensslconf.h
x509_req.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_req.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
x509_req.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_req.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_req.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_req.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509_req.o: ../include/internal/x509_int.h x509_req.c
x509_set.o: ../../e_os.h ../../include/openssl/asn1.h
x509_set.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_set.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_set.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_set.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_set.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_set.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_set.o: ../../include/openssl/opensslconf.h
x509_set.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_set.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_set.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_set.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_set.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509_set.o: ../include/internal/x509_int.h x509_set.c
x509_trs.o: ../../e_os.h ../../include/openssl/asn1.h
x509_trs.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_trs.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_trs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_trs.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_trs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_trs.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_trs.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_trs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_trs.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_trs.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_trs.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_trs.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_trs.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h
x509_trs.o: x509_trs.c
x509_txt.o: ../../e_os.h ../../include/openssl/asn1.h
x509_txt.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_txt.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_txt.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_txt.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_txt.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_txt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_txt.o: ../../include/openssl/opensslconf.h
x509_txt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_txt.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_txt.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_txt.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_txt.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509_txt.o: x509_txt.c
x509_v3.o: ../../e_os.h ../../include/openssl/asn1.h
x509_v3.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_v3.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_v3.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_v3.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_v3.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_v3.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_v3.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_v3.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_v3.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_v3.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_v3.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_v3.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_v3.o: ../include/internal/cryptlib.h x509_lcl.h x509_v3.c
x509_vfy.o: ../../e_os.h ../../include/openssl/asn1.h
x509_vfy.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vfy.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vfy.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vfy.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vfy.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vfy.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vfy.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vfy.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vfy.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vfy.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h
x509_vfy.o: x509_lcl.h x509_vfy.c
x509_vpm.o: ../../e_os.h ../../include/openssl/asn1.h
x509_vpm.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vpm.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vpm.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vpm.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vpm.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vpm.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vpm.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vpm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vpm.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vpm.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vpm.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vpm.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vpm.o: ../include/internal/cryptlib.h x509_lcl.h x509_vpm.c
x509cset.o: ../../e_os.h ../../include/openssl/asn1.h
x509cset.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509cset.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509cset.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509cset.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509cset.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509cset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509cset.o: ../../include/openssl/opensslconf.h
x509cset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509cset.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509cset.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509cset.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509cset.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509cset.o: ../include/internal/x509_int.h x509cset.c
x509name.o: ../../e_os.h ../../include/openssl/asn1.h
x509name.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509name.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509name.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509name.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509name.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509name.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509name.o: ../../include/openssl/opensslconf.h
x509name.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509name.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509name.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509name.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509name.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509name.o: ../include/internal/x509_int.h x509name.c
x509rset.o: ../../e_os.h ../../include/openssl/asn1.h
x509rset.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509rset.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509rset.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509rset.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509rset.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509rset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509rset.o: ../../include/openssl/opensslconf.h
x509rset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509rset.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509rset.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509rset.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509rset.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509rset.o: ../include/internal/x509_int.h x509rset.c
x509spki.o: ../../e_os.h ../../include/openssl/asn1.h
x509spki.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509spki.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509spki.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509spki.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509spki.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509spki.o: ../../include/openssl/opensslconf.h
x509spki.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509spki.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509spki.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509spki.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509spki.o: x509spki.c
x509type.o: ../../e_os.h ../../include/openssl/asn1.h
x509type.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509type.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509type.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509type.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509type.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509type.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509type.o: ../../include/openssl/opensslconf.h
x509type.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509type.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509type.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509type.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509type.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x509type.o: x509type.c
x_all.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_all.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
x_all.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
x_all.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_all.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_all.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_all.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_all.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
x_all.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_all.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_all.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_all.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_all.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_all.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x_all.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h x_all.c
x_attrib.o: ../../e_os.h ../../include/openssl/asn1.h
x_attrib.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_attrib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_attrib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_attrib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_attrib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_attrib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_attrib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_attrib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_attrib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_attrib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_attrib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_attrib.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_attrib.o: x509_lcl.h x_attrib.c
x_crl.o: ../../e_os.h ../../include/openssl/asn1.h
x_crl.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_crl.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
x_crl.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x_crl.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_crl.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x_crl.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_crl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_crl.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_crl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_crl.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x_crl.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x_crl.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x_crl.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
x_crl.o: ../include/internal/x509_int.h x509_lcl.h x_crl.c
x_exten.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
x_exten.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x_exten.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x_exten.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_exten.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
x_exten.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_exten.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_exten.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_exten.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_exten.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_exten.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_exten.o: ../../include/openssl/x509_vfy.h x509_lcl.h x_exten.c
x_name.o: ../../e_os.h ../../include/openssl/asn1.h
x_name.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_name.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_name.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_name.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_name.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_name.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_name.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_name.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_name.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_name.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_name.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_name.o: ../../include/openssl/x509_vfy.h ../include/internal/asn1_int.h
x_name.o: ../include/internal/cryptlib.h ../include/internal/x509_int.h
x_name.o: x_name.c
x_req.o: ../../e_os.h ../../include/openssl/asn1.h
x_req.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_req.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_req.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_req.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_req.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_req.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_req.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_req.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_req.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_req.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_req.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_req.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_req.o: ../include/internal/x509_int.h x_req.c
x_x509.o: ../../e_os.h ../../include/openssl/asn1.h
x_x509.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_x509.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
x_x509.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x_x509.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_x509.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x_x509.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_x509.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_x509.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_x509.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_x509.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x_x509.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x_x509.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x_x509.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
x_x509.o: ../include/internal/x509_int.h x_x509.c
x_x509a.o: ../../e_os.h ../../include/openssl/asn1.h
x_x509a.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x_x509a.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_x509a.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_x509a.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_x509a.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_x509a.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_x509a.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_x509a.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_x509a.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x_x509a.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_x509a.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_x509a.o: ../../include/openssl/x509_vfy.h ../include/internal/cryptlib.h
x_x509a.o: ../include/internal/x509_int.h x_x509a.c
