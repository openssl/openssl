#
# OpenSSL/ssl/Makefile
#

DIR=	ssl
TOP=	..
CC=	cc
INCLUDES= -I../crypto -I$(TOP) -I../include $(KRB5_INCLUDES)
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r
# KRB5 stuff
KRB5_INCLUDES=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README ssl-lib.com install.com

LIB=$(TOP)/libssl.a
SHARED_LIB= libssl$(SHLIB_EXT)
LIBSRC=	\
	s3_meth.c   s3_srvr.c s3_clnt.c  s3_lib.c  s3_enc.c record/rec_layer_s3.c \
	s3_both.c s3_cbc.c s3_msg.c \
	s23_meth.c s23_srvr.c s23_clnt.c s23_lib.c record/rec_layer_s23.c \
	t1_meth.c   t1_srvr.c t1_clnt.c  t1_lib.c  t1_enc.c t1_ext.c \
	d1_meth.c   d1_srvr.c d1_clnt.c  d1_lib.c  record/rec_layer_d1.c d1_msg.c \
	d1_both.c d1_srtp.c \
	ssl_lib.c ssl_err2.c ssl_cert.c ssl_sess.c \
	ssl_ciph.c ssl_stat.c ssl_rsa.c \
	ssl_asn1.c ssl_txt.c ssl_algs.c ssl_conf.c \
	bio_ssl.c ssl_err.c kssl.c t1_reneg.c tls_srp.c t1_trce.c ssl_utst.c \
	record/ssl3_buffer.c record/ssl3_record.c record/dtls1_bitmap.c
LIBOBJ= \
	s3_meth.o  s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o record/rec_layer_s3.o \
	s3_both.o s3_cbc.o s3_msg.o \
	s23_meth.o s23_srvr.o s23_clnt.o s23_lib.o record/rec_layer_s23.o \
	t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o t1_ext.o \
	d1_meth.o   d1_srvr.o d1_clnt.o  d1_lib.o  record/rec_layer_d1.o d1_msg.o \
	d1_both.o d1_srtp.o\
	ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o \
	ssl_ciph.o ssl_stat.o ssl_rsa.o \
	ssl_asn1.o ssl_txt.o ssl_algs.o ssl_conf.o \
	bio_ssl.o ssl_err.o kssl.o t1_reneg.o tls_srp.o t1_trce.o ssl_utst.o \
	record/ssl3_buffer.o record/ssl3_record.o record/dtls1_bitmap.o

SRC= $(LIBSRC)

HEADER=	ssl_locl.h kssl_lcl.h  record/record_locl.h record/record.h

ALL=	$(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	shared

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

shared: lib
	if [ -n "$(SHARED_LIBS)" ]; then \
		(cd ..; $(MAKE) $(SHARED_LIB)); \
	fi

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f $(LIBOBJ) *.obj lib tags core .pure .nfs* *.old *.bak fluff
	rm -f record/*.obj record/lib record/retags record/core \
	record/.pure record/.nfs* record/*.old record/*.bak record/fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

bio_ssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
bio_ssl.o: ../include/openssl/buffer.h ../include/openssl/comp.h
bio_ssl.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
bio_ssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
bio_ssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
bio_ssl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
bio_ssl.o: ../include/openssl/evp.h ../include/openssl/hmac.h
bio_ssl.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
bio_ssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
bio_ssl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
bio_ssl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
bio_ssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
bio_ssl.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
bio_ssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
bio_ssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
bio_ssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
bio_ssl.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
bio_ssl.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
bio_ssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h bio_ssl.c
bio_ssl.o: record/record.h ssl_locl.h
d1_both.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_both.o: ../include/openssl/buffer.h ../include/openssl/comp.h
d1_both.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
d1_both.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_both.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_both.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_both.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_both.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_both.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_both.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_both.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_both.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_both.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
d1_both.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
d1_both.o: ../include/openssl/sha.h ../include/openssl/srtp.h
d1_both.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
d1_both.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
d1_both.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
d1_both.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_both.o: ../include/openssl/x509_vfy.h d1_both.c record/record.h ssl_locl.h
d1_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_clnt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_clnt.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_clnt.o: ../include/openssl/dh.h ../include/openssl/dsa.h
d1_clnt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_clnt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_clnt.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_clnt.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_clnt.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_clnt.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
d1_clnt.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
d1_clnt.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
d1_clnt.o: ../include/openssl/pem.h ../include/openssl/pem2.h
d1_clnt.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
d1_clnt.o: ../include/openssl/rand.h ../include/openssl/rsa.h
d1_clnt.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_clnt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_clnt.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_clnt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_clnt.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_clnt.c
d1_clnt.o: kssl_lcl.h record/record.h ssl_locl.h
d1_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_lib.o: ../include/openssl/buffer.h ../include/openssl/comp.h
d1_lib.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
d1_lib.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_lib.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_lib.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_lib.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_lib.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_lib.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_lib.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_lib.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_lib.c
d1_lib.o: record/record.h ssl_locl.h
d1_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_meth.o: ../include/openssl/buffer.h ../include/openssl/comp.h
d1_meth.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
d1_meth.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_meth.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_meth.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_meth.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_meth.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_meth.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_meth.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_meth.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_meth.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_meth.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_meth.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_meth.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_meth.c
d1_meth.o: record/record.h ssl_locl.h
d1_msg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_msg.o: ../include/openssl/buffer.h ../include/openssl/comp.h
d1_msg.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
d1_msg.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_msg.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_msg.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_msg.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_msg.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_msg.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_msg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_msg.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_msg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_msg.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_msg.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_msg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_msg.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_msg.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_msg.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_msg.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_msg.c
d1_msg.o: record/record.h ssl_locl.h
d1_srtp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_srtp.o: ../include/openssl/buffer.h ../include/openssl/comp.h
d1_srtp.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
d1_srtp.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_srtp.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_srtp.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_srtp.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_srtp.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_srtp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_srtp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_srtp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_srtp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_srtp.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_srtp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_srtp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_srtp.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_srtp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_srtp.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_srtp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_srtp.c
d1_srtp.o: record/record.h ssl_locl.h
d1_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_srvr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_srvr.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_srvr.o: ../include/openssl/dh.h ../include/openssl/dsa.h
d1_srvr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_srvr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_srvr.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_srvr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_srvr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
d1_srvr.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
d1_srvr.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
d1_srvr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
d1_srvr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
d1_srvr.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
d1_srvr.o: ../include/openssl/rand.h ../include/openssl/rsa.h
d1_srvr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_srvr.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_srvr.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_srvr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_srvr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_srvr.c
d1_srvr.o: record/record.h ssl_locl.h
dtls1_bitmap.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dtls1_bitmap.o: ../include/openssl/buffer.h ../include/openssl/comp.h
dtls1_bitmap.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
dtls1_bitmap.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
dtls1_bitmap.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dtls1_bitmap.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dtls1_bitmap.o: ../include/openssl/evp.h ../include/openssl/hmac.h
dtls1_bitmap.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
dtls1_bitmap.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dtls1_bitmap.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dtls1_bitmap.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dtls1_bitmap.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dtls1_bitmap.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
dtls1_bitmap.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dtls1_bitmap.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
dtls1_bitmap.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
dtls1_bitmap.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
dtls1_bitmap.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
dtls1_bitmap.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dtls1_bitmap.o: dtls1_bitmap.c record/../record/record.h record/../ssl_locl.h
dtls1_bitmap.o: record/dtls1_bitmap.c record/record_locl.h
kssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
kssl.o: ../include/openssl/buffer.h ../include/openssl/comp.h
kssl.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
kssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
kssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
kssl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
kssl.o: ../include/openssl/evp.h ../include/openssl/hmac.h
kssl.o: ../include/openssl/krb5_asn.h ../include/openssl/kssl.h
kssl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
kssl.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
kssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
kssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
kssl.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
kssl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
kssl.o: ../include/openssl/sha.h ../include/openssl/srtp.h
kssl.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
kssl.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
kssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
kssl.o: ../include/openssl/tls1.h ../include/openssl/x509.h
kssl.o: ../include/openssl/x509_vfy.h kssl.c kssl_lcl.h record/record.h
kssl.o: ssl_locl.h
rec_layer_d1.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rec_layer_d1.o: ../include/openssl/buffer.h ../include/openssl/comp.h
rec_layer_d1.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
rec_layer_d1.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
rec_layer_d1.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rec_layer_d1.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rec_layer_d1.o: ../include/openssl/evp.h ../include/openssl/hmac.h
rec_layer_d1.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
rec_layer_d1.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rec_layer_d1.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rec_layer_d1.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rec_layer_d1.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rec_layer_d1.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
rec_layer_d1.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rec_layer_d1.o: ../include/openssl/sha.h ../include/openssl/srtp.h
rec_layer_d1.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
rec_layer_d1.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
rec_layer_d1.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rec_layer_d1.o: ../include/openssl/tls1.h ../include/openssl/x509.h
rec_layer_d1.o: ../include/openssl/x509_vfy.h rec_layer_d1.c
rec_layer_d1.o: record/../record/record.h record/../ssl_locl.h
rec_layer_d1.o: record/rec_layer_d1.c record/record_locl.h
rec_layer_s23.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rec_layer_s23.o: ../include/openssl/buffer.h ../include/openssl/comp.h
rec_layer_s23.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
rec_layer_s23.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
rec_layer_s23.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rec_layer_s23.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rec_layer_s23.o: ../include/openssl/evp.h ../include/openssl/hmac.h
rec_layer_s23.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
rec_layer_s23.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rec_layer_s23.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rec_layer_s23.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rec_layer_s23.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rec_layer_s23.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
rec_layer_s23.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rec_layer_s23.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
rec_layer_s23.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
rec_layer_s23.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
rec_layer_s23.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
rec_layer_s23.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rec_layer_s23.o: rec_layer_s23.c record/../record/record.h record/../ssl_locl.h
rec_layer_s23.o: record/rec_layer_s23.c
rec_layer_s3.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rec_layer_s3.o: ../include/openssl/buffer.h ../include/openssl/comp.h
rec_layer_s3.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
rec_layer_s3.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
rec_layer_s3.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rec_layer_s3.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rec_layer_s3.o: ../include/openssl/evp.h ../include/openssl/hmac.h
rec_layer_s3.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
rec_layer_s3.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rec_layer_s3.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rec_layer_s3.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rec_layer_s3.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rec_layer_s3.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
rec_layer_s3.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rec_layer_s3.o: ../include/openssl/sha.h ../include/openssl/srtp.h
rec_layer_s3.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
rec_layer_s3.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
rec_layer_s3.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rec_layer_s3.o: ../include/openssl/tls1.h ../include/openssl/x509.h
rec_layer_s3.o: ../include/openssl/x509_vfy.h rec_layer_s3.c
rec_layer_s3.o: record/../record/record.h record/../ssl_locl.h
rec_layer_s3.o: record/rec_layer_s3.c record/record_locl.h
s23_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_clnt.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s23_clnt.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s23_clnt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s23_clnt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s23_clnt.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s23_clnt.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s23_clnt.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s23_clnt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s23_clnt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s23_clnt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s23_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s23_clnt.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s23_clnt.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s23_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s23_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s23_clnt.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s23_clnt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s23_clnt.o: ../include/openssl/x509_vfy.h record/record.h s23_clnt.c ssl_locl.h
s23_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_lib.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s23_lib.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s23_lib.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s23_lib.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s23_lib.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s23_lib.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s23_lib.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s23_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s23_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s23_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s23_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_lib.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s23_lib.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s23_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s23_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s23_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s23_lib.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s23_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s23_lib.o: record/record.h s23_lib.c ssl_locl.h
s23_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_meth.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s23_meth.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s23_meth.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s23_meth.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s23_meth.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s23_meth.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s23_meth.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s23_meth.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s23_meth.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s23_meth.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s23_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_meth.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s23_meth.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s23_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s23_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s23_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s23_meth.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s23_meth.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s23_meth.o: record/record.h s23_meth.c ssl_locl.h
s23_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_srvr.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s23_srvr.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s23_srvr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s23_srvr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s23_srvr.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s23_srvr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s23_srvr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s23_srvr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s23_srvr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s23_srvr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s23_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s23_srvr.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s23_srvr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s23_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s23_srvr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s23_srvr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s23_srvr.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s23_srvr.o: ../include/openssl/x509_vfy.h record/record.h s23_srvr.c ssl_locl.h
s3_both.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_both.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s3_both.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s3_both.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_both.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_both.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s3_both.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s3_both.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_both.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_both.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_both.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_both.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_both.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_both.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_both.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_both.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_both.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_both.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s3_both.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_both.o: ../include/openssl/x509_vfy.h record/record.h s3_both.c ssl_locl.h
s3_cbc.o: ../crypto/constant_time_locl.h ../e_os.h ../include/openssl/asn1.h
s3_cbc.o: ../include/openssl/bio.h ../include/openssl/buffer.h
s3_cbc.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_cbc.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_cbc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_cbc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_cbc.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_cbc.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s3_cbc.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_cbc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_cbc.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_cbc.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_cbc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_cbc.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s3_cbc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_cbc.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_cbc.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_cbc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_cbc.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_cbc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s3_cbc.o: record/record.h s3_cbc.c ssl_locl.h
s3_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_clnt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_clnt.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_clnt.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s3_clnt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_clnt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_clnt.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s3_clnt.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_clnt.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s3_clnt.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_clnt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_clnt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_clnt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_clnt.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_clnt.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_clnt.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s3_clnt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_clnt.o: ../include/openssl/x509_vfy.h kssl_lcl.h record/record.h s3_clnt.c
s3_clnt.o: ssl_locl.h
s3_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_enc.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s3_enc.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s3_enc.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_enc.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_enc.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s3_enc.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s3_enc.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_enc.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s3_enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s3_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_enc.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_enc.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_enc.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_enc.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s3_enc.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_enc.o: ../include/openssl/x509_vfy.h record/record.h s3_enc.c ssl_locl.h
s3_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_lib.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s3_lib.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s3_lib.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_lib.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_lib.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_lib.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_lib.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s3_lib.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_lib.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s3_lib.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_lib.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h kssl_lcl.h
s3_lib.o: record/record.h s3_lib.c ssl_locl.h
s3_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_meth.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s3_meth.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s3_meth.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_meth.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_meth.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s3_meth.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s3_meth.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_meth.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_meth.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_meth.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_meth.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s3_meth.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_meth.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_meth.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s3_meth.o: record/record.h s3_meth.c ssl_locl.h
s3_msg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_msg.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s3_msg.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
s3_msg.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_msg.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_msg.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s3_msg.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s3_msg.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_msg.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_msg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_msg.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_msg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_msg.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s3_msg.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_msg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_msg.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_msg.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_msg.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_msg.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s3_msg.o: record/record.h s3_msg.c ssl_locl.h
s3_srvr.o: ../crypto/constant_time_locl.h ../e_os.h ../include/openssl/asn1.h
s3_srvr.o: ../include/openssl/bio.h ../include/openssl/bn.h
s3_srvr.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s3_srvr.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s3_srvr.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_srvr.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_srvr.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_srvr.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_srvr.o: ../include/openssl/hmac.h ../include/openssl/krb5_asn.h
s3_srvr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_srvr.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_srvr.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s3_srvr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s3_srvr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_srvr.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_srvr.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s3_srvr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_srvr.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_srvr.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_srvr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_srvr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h kssl_lcl.h
s3_srvr.o: record/record.h s3_srvr.c ssl_locl.h
ssl3_buffer.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl3_buffer.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl3_buffer.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl3_buffer.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl3_buffer.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl3_buffer.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl3_buffer.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl3_buffer.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl3_buffer.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl3_buffer.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl3_buffer.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl3_buffer.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl3_buffer.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl3_buffer.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl3_buffer.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl3_buffer.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl3_buffer.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl3_buffer.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl3_buffer.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl3_buffer.o: record/../record/record.h record/../ssl_locl.h
ssl3_buffer.o: record/record_locl.h record/ssl3_buffer.c ssl3_buffer.c
ssl3_record.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl3_record.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl3_record.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl3_record.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl3_record.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl3_record.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl3_record.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl3_record.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl3_record.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl3_record.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl3_record.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl3_record.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl3_record.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
ssl3_record.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl3_record.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl3_record.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl3_record.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl3_record.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl3_record.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl3_record.o: ../include/openssl/x509_vfy.h
ssl3_record.o: record/../../crypto/constant_time_locl.h
ssl3_record.o: record/../record/record.h record/../ssl_locl.h
ssl3_record.o: record/record_locl.h record/ssl3_record.c ssl3_record.c
ssl_algs.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_algs.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_algs.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_algs.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_algs.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_algs.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_algs.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_algs.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_algs.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_algs.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_algs.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_algs.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_algs.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_algs.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_algs.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_algs.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_algs.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_algs.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_algs.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_algs.o: record/record.h ssl_algs.c ssl_locl.h
ssl_asn1.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/asn1t.h
ssl_asn1.o: ../include/openssl/bio.h ../include/openssl/buffer.h
ssl_asn1.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_asn1.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_asn1.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_asn1.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_asn1.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_asn1.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ssl_asn1.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_asn1.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_asn1.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_asn1.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_asn1.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_asn1.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_asn1.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_asn1.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_asn1.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_asn1.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_asn1.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_asn1.o: ../include/openssl/x509_vfy.h record/record.h ssl_asn1.c ssl_locl.h
ssl_cert.o: ../crypto/o_dir.h ../e_os.h ../include/openssl/asn1.h
ssl_cert.o: ../include/openssl/bio.h ../include/openssl/bn.h
ssl_cert.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_cert.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ssl_cert.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ssl_cert.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_cert.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_cert.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_cert.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_cert.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_cert.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_cert.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_cert.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_cert.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_cert.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_cert.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_cert.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_cert.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_cert.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_cert.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_cert.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_cert.o: ../include/openssl/x509v3.h record/record.h ssl_cert.c ssl_locl.h
ssl_ciph.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_ciph.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_ciph.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_ciph.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_ciph.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_ciph.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ssl_ciph.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_ciph.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ssl_ciph.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_ciph.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_ciph.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_ciph.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_ciph.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_ciph.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_ciph.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_ciph.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_ciph.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_ciph.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_ciph.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_ciph.o: ../include/openssl/x509_vfy.h record/record.h ssl_ciph.c ssl_locl.h
ssl_conf.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_conf.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_conf.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ssl_conf.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ssl_conf.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_conf.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_conf.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_conf.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_conf.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_conf.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_conf.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_conf.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_conf.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_conf.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_conf.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_conf.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_conf.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_conf.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_conf.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_conf.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_conf.o: record/record.h ssl_conf.c ssl_locl.h
ssl_err.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_err.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_err.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ssl_err.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_err.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_err.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_err.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ssl_err.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_err.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_err.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_err.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_err.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ssl_err.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_err.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_err.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_err.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_err.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_err.o: ../include/openssl/x509_vfy.h ssl_err.c
ssl_err2.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_err2.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_err2.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ssl_err2.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_err2.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_err2.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_err2.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ssl_err2.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_err2.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_err2.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_err2.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_err2.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ssl_err2.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_err2.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_err2.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_err2.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_err2.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_err2.o: ../include/openssl/x509_vfy.h ssl_err2.c
ssl_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_lib.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_lib.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ssl_lib.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ssl_lib.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_lib.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_lib.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ssl_lib.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_lib.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ssl_lib.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_lib.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ssl_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_lib.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
ssl_lib.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_lib.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_lib.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_lib.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_lib.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_lib.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h kssl_lcl.h
ssl_lib.o: record/record.h ssl_lib.c ssl_locl.h
ssl_rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_rsa.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_rsa.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_rsa.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_rsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_rsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_rsa.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_rsa.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_rsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_rsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_rsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_rsa.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_rsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_rsa.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_rsa.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_rsa.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_rsa.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_rsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_rsa.o: record/record.h ssl_locl.h ssl_rsa.c
ssl_sess.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_sess.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_sess.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_sess.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_sess.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_sess.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ssl_sess.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_sess.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ssl_sess.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_sess.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_sess.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_sess.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_sess.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_sess.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ssl_sess.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_sess.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_sess.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_sess.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_sess.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_sess.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_sess.o: record/record.h ssl_locl.h ssl_sess.c
ssl_stat.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_stat.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_stat.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_stat.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_stat.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_stat.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_stat.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_stat.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_stat.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_stat.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_stat.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_stat.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_stat.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_stat.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_stat.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_stat.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_stat.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_stat.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_stat.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_stat.o: record/record.h ssl_locl.h ssl_stat.c
ssl_txt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_txt.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_txt.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_txt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_txt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_txt.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_txt.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_txt.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_txt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_txt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_txt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_txt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_txt.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_txt.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_txt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_txt.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_txt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_txt.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_txt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_txt.o: record/record.h ssl_locl.h ssl_txt.c
ssl_utst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_utst.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_utst.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_utst.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_utst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_utst.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_utst.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_utst.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_utst.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_utst.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_utst.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_utst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_utst.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_utst.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_utst.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_utst.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_utst.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_utst.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_utst.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_utst.o: record/record.h ssl_locl.h ssl_utst.c
t1_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_clnt.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_clnt.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_clnt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_clnt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_clnt.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_clnt.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_clnt.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_clnt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_clnt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_clnt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_clnt.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
t1_clnt.o: ../include/openssl/sha.h ../include/openssl/srtp.h
t1_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
t1_clnt.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_clnt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_clnt.o: ../include/openssl/x509_vfy.h record/record.h ssl_locl.h t1_clnt.c
t1_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_enc.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_enc.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_enc.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_enc.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_enc.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_enc.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_enc.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_enc.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
t1_enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
t1_enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
t1_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
t1_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
t1_enc.o: ../include/openssl/rand.h ../include/openssl/rsa.h
t1_enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_enc.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_enc.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_enc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_enc.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_enc.o: record/record.h ssl_locl.h t1_enc.c
t1_ext.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_ext.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_ext.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_ext.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_ext.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_ext.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_ext.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_ext.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_ext.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_ext.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_ext.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_ext.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_ext.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_ext.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_ext.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_ext.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_ext.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_ext.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_ext.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_ext.o: record/record.h ssl_locl.h t1_ext.c
t1_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_lib.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_lib.o: ../include/openssl/comp.h ../include/openssl/conf.h
t1_lib.o: ../include/openssl/crypto.h ../include/openssl/dh.h
t1_lib.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_lib.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_lib.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_lib.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_lib.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
t1_lib.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
t1_lib.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
t1_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_lib.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_lib.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
t1_lib.o: ../include/openssl/sha.h ../include/openssl/srtp.h
t1_lib.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_lib.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
t1_lib.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_lib.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
t1_lib.o: record/record.h ssl_locl.h t1_lib.c
t1_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_meth.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_meth.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_meth.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_meth.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_meth.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_meth.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_meth.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_meth.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_meth.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_meth.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_meth.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_meth.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_meth.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_meth.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_meth.o: record/record.h ssl_locl.h t1_meth.c
t1_reneg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_reneg.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_reneg.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_reneg.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_reneg.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_reneg.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_reneg.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_reneg.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_reneg.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_reneg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_reneg.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_reneg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_reneg.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_reneg.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_reneg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_reneg.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_reneg.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_reneg.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_reneg.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_reneg.o: record/record.h ssl_locl.h t1_reneg.c
t1_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_srvr.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_srvr.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_srvr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_srvr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_srvr.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_srvr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_srvr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_srvr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_srvr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_srvr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_srvr.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
t1_srvr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
t1_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_srvr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
t1_srvr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_srvr.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_srvr.o: ../include/openssl/x509_vfy.h record/record.h ssl_locl.h t1_srvr.c
t1_trce.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_trce.o: ../include/openssl/buffer.h ../include/openssl/comp.h
t1_trce.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
t1_trce.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
t1_trce.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
t1_trce.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
t1_trce.o: ../include/openssl/evp.h ../include/openssl/hmac.h
t1_trce.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_trce.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_trce.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_trce.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_trce.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_trce.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_trce.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_trce.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_trce.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_trce.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_trce.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_trce.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_trce.o: record/record.h ssl_locl.h t1_trce.c
tls_srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
tls_srp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
tls_srp.o: ../include/openssl/comp.h ../include/openssl/crypto.h
tls_srp.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
tls_srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
tls_srp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
tls_srp.o: ../include/openssl/err.h ../include/openssl/evp.h
tls_srp.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
tls_srp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
tls_srp.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
tls_srp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
tls_srp.o: ../include/openssl/pem.h ../include/openssl/pem2.h
tls_srp.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
tls_srp.o: ../include/openssl/rand.h ../include/openssl/rsa.h
tls_srp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
tls_srp.o: ../include/openssl/srp.h ../include/openssl/srtp.h
tls_srp.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
tls_srp.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
tls_srp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
tls_srp.o: ../include/openssl/tls1.h ../include/openssl/x509.h
tls_srp.o: ../include/openssl/x509_vfy.h record/record.h ssl_locl.h tls_srp.c
