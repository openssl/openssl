#
# SSLeay/crypto/x509/Makefile
#

DIR=	x509
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	x509_def.c x509_d2.c x509_r2x.c x509_cmp.c \
	x509_obj.c x509_req.c x509spki.c x509_vfy.c \
	x509_set.c x509cset.c x509rset.c x509_err.c \
	x509name.c x509_v3.c x509_ext.c x509_att.c \
	x509type.c x509_lu.c x_all.c x509_txt.c \
	x509_trs.c by_file.c by_dir.c 
LIBOBJ= x509_def.o x509_d2.o x509_r2x.o x509_cmp.o \
	x509_obj.o x509_req.o x509spki.o x509_vfy.o \
	x509_set.o x509cset.o x509rset.o x509_err.o \
	x509name.o x509_v3.o x509_ext.o x509_att.o \
	x509type.o x509_lu.o x_all.o x509_txt.o \
	x509_trs.o by_file.o by_dir.o

SRC= $(LIBSRC)

EXHEADER= x509.h x509_vfy.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
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
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

by_dir.o: ../../e_os.h ../../include/openssl/aes.h ../../include/openssl/asn1.h
by_dir.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
by_dir.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
by_dir.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
by_dir.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
by_dir.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
by_dir.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
by_dir.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
by_dir.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
by_dir.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
by_dir.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
by_dir.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
by_dir.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
by_dir.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
by_dir.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
by_dir.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
by_dir.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
by_dir.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
by_dir.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
by_dir.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
by_dir.o: ../cryptlib.h by_dir.c
by_file.o: ../../e_os.h ../../include/openssl/aes.h
by_file.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
by_file.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
by_file.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
by_file.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
by_file.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
by_file.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
by_file.o: ../../include/openssl/err.h ../../include/openssl/evp.h
by_file.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
by_file.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
by_file.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
by_file.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
by_file.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
by_file.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
by_file.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
by_file.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
by_file.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
by_file.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
by_file.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
by_file.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
by_file.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
by_file.o: ../../include/openssl/x509_vfy.h ../cryptlib.h by_file.c
x509_att.o: ../../e_os.h ../../include/openssl/aes.h
x509_att.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_att.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_att.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_att.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_att.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_att.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_att.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_att.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_att.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_att.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_att.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_att.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_att.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_att.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_att.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_att.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_att.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_att.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_att.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_att.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_att.c
x509_cmp.o: ../../e_os.h ../../include/openssl/aes.h
x509_cmp.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_cmp.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_cmp.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_cmp.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_cmp.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_cmp.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_cmp.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_cmp.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_cmp.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_cmp.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_cmp.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_cmp.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_cmp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_cmp.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_cmp.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_cmp.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_cmp.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_cmp.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_cmp.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_cmp.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_cmp.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_cmp.c
x509_d2.o: ../../e_os.h ../../include/openssl/aes.h
x509_d2.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_d2.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_d2.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_d2.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_d2.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_d2.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_d2.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_d2.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_d2.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_d2.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_d2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_d2.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x509_d2.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x509_d2.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
x509_d2.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
x509_d2.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x509_d2.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_d2.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
x509_d2.o: ../../include/openssl/ui_compat.h ../../include/openssl/x509.h
x509_d2.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_d2.c
x509_def.o: ../../e_os.h ../../include/openssl/aes.h
x509_def.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_def.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_def.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_def.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_def.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_def.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_def.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_def.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_def.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_def.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_def.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_def.o: ../../include/openssl/opensslconf.h
x509_def.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_def.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_def.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_def.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_def.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_def.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_def.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_def.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_def.o: ../cryptlib.h x509_def.c
x509_err.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
x509_err.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
x509_err.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x509_err.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
x509_err.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_err.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_err.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_err.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_err.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_err.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_err.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_err.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_err.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_err.o: x509_err.c
x509_ext.o: ../../e_os.h ../../include/openssl/aes.h
x509_ext.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_ext.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_ext.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_ext.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_ext.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_ext.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_ext.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_ext.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_ext.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_ext.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_ext.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_ext.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_ext.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_ext.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_ext.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_ext.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_ext.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_ext.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_ext.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_ext.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_ext.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_ext.c
x509_lu.o: ../../e_os.h ../../include/openssl/aes.h
x509_lu.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_lu.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_lu.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_lu.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_lu.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_lu.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_lu.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_lu.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_lu.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_lu.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_lu.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_lu.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_lu.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_lu.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_lu.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_lu.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_lu.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_lu.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_lu.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_lu.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_lu.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_lu.c
x509_obj.o: ../../e_os.h ../../include/openssl/aes.h
x509_obj.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_obj.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_obj.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_obj.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_obj.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_obj.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_obj.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_obj.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_obj.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_obj.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_obj.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_obj.o: ../../include/openssl/opensslconf.h
x509_obj.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_obj.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_obj.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_obj.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_obj.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_obj.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_obj.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_obj.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_obj.o: ../cryptlib.h x509_obj.c
x509_r2x.o: ../../e_os.h ../../include/openssl/aes.h
x509_r2x.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_r2x.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_r2x.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_r2x.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_r2x.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_r2x.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_r2x.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_r2x.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_r2x.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_r2x.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_r2x.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_r2x.o: ../../include/openssl/opensslconf.h
x509_r2x.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_r2x.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_r2x.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_r2x.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_r2x.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_r2x.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_r2x.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_r2x.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_r2x.o: ../cryptlib.h x509_r2x.c
x509_req.o: ../../e_os.h ../../include/openssl/aes.h
x509_req.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_req.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_req.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_req.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_req.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_req.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_req.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_req.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_req.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_req.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_req.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_req.o: ../../include/openssl/opensslconf.h
x509_req.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_req.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
x509_req.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_req.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_req.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_req.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_req.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_req.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_req.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_req.o: ../cryptlib.h x509_req.c
x509_set.o: ../../e_os.h ../../include/openssl/aes.h
x509_set.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_set.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_set.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_set.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_set.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_set.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_set.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_set.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_set.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_set.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_set.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_set.o: ../../include/openssl/opensslconf.h
x509_set.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_set.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_set.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_set.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_set.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_set.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_set.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_set.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_set.o: ../cryptlib.h x509_set.c
x509_trs.o: ../../e_os.h ../../include/openssl/aes.h
x509_trs.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_trs.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_trs.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_trs.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_trs.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_trs.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_trs.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_trs.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_trs.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_trs.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_trs.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_trs.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_trs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_trs.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_trs.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_trs.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_trs.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_trs.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_trs.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_trs.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_trs.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_trs.c
x509_txt.o: ../../e_os.h ../../include/openssl/aes.h
x509_txt.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_txt.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_txt.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_txt.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509_txt.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509_txt.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509_txt.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_txt.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509_txt.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509_txt.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509_txt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_txt.o: ../../include/openssl/opensslconf.h
x509_txt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_txt.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_txt.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_txt.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_txt.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_txt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_txt.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_txt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_txt.o: ../cryptlib.h x509_txt.c
x509_v3.o: ../../e_os.h ../../include/openssl/aes.h
x509_v3.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_v3.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_v3.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_v3.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_v3.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_v3.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_v3.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_v3.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_v3.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_v3.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_v3.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_v3.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_v3.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_v3.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_v3.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_v3.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_v3.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_v3.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_v3.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_v3.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_v3.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_v3.c
x509_vfy.o: ../../e_os.h ../../include/openssl/aes.h
x509_vfy.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_vfy.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509_vfy.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509_vfy.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vfy.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x509_vfy.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x509_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x509_vfy.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x509_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x509_vfy.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x509_vfy.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x509_vfy.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vfy.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509_vfy.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509_vfy.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509_vfy.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_vfy.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_vfy.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509_vfy.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_vfy.o: ../../include/openssl/x509v3.h ../cryptlib.h x509_vfy.c
x509cset.o: ../../e_os.h ../../include/openssl/aes.h
x509cset.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509cset.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509cset.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509cset.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509cset.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509cset.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509cset.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509cset.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509cset.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509cset.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509cset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509cset.o: ../../include/openssl/opensslconf.h
x509cset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509cset.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509cset.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509cset.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509cset.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509cset.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509cset.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509cset.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509cset.o: ../cryptlib.h x509cset.c
x509name.o: ../../e_os.h ../../include/openssl/aes.h
x509name.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509name.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509name.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509name.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509name.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509name.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509name.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509name.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509name.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509name.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509name.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509name.o: ../../include/openssl/opensslconf.h
x509name.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509name.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509name.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509name.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509name.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509name.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509name.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509name.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509name.o: ../cryptlib.h x509name.c
x509rset.o: ../../e_os.h ../../include/openssl/aes.h
x509rset.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509rset.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509rset.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509rset.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509rset.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509rset.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509rset.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509rset.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509rset.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509rset.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509rset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509rset.o: ../../include/openssl/opensslconf.h
x509rset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509rset.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509rset.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509rset.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509rset.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509rset.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509rset.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509rset.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509rset.o: ../cryptlib.h x509rset.c
x509spki.o: ../../e_os.h ../../include/openssl/aes.h
x509spki.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509spki.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509spki.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509spki.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509spki.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509spki.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509spki.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509spki.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509spki.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509spki.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509spki.o: ../../include/openssl/opensslconf.h
x509spki.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509spki.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509spki.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509spki.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509spki.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509spki.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509spki.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509spki.o: ../cryptlib.h x509spki.c
x509type.o: ../../e_os.h ../../include/openssl/aes.h
x509type.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509type.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
x509type.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
x509type.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
x509type.o: ../../include/openssl/des_old.h ../../include/openssl/dh.h
x509type.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x509type.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509type.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
x509type.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
x509type.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
x509type.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509type.o: ../../include/openssl/opensslconf.h
x509type.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509type.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x509type.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x509type.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x509type.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509type.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509type.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x509type.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509type.o: ../cryptlib.h x509type.c
x_all.o: ../../e_os.h ../../include/openssl/aes.h ../../include/openssl/asn1.h
x_all.o: ../../include/openssl/bio.h ../../include/openssl/blowfish.h
x_all.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x_all.o: ../../include/openssl/cast.h ../../include/openssl/crypto.h
x_all.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
x_all.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
x_all.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
x_all.o: ../../include/openssl/evp.h ../../include/openssl/idea.h
x_all.o: ../../include/openssl/lhash.h ../../include/openssl/md2.h
x_all.o: ../../include/openssl/md4.h ../../include/openssl/md5.h
x_all.o: ../../include/openssl/mdc2.h ../../include/openssl/obj_mac.h
x_all.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x_all.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x_all.o: ../../include/openssl/pkcs7.h ../../include/openssl/rc2.h
x_all.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
x_all.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
x_all.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x_all.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x_all.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
x_all.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x_all.o: ../cryptlib.h x_all.c
