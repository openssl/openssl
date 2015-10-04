#
# OpenSSL/ssl/Makefile
#

DIR=	ssl
TOP=	..
CC=	cc
INCLUDES= -I$(TOP) -I../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README ssl-lib.com install.com

LIB=$(TOP)/libssl.a
SHARED_LIB= libssl$(SHLIB_EXT)
LIBSRC=	\
	s3_srvr.c s3_clnt.c  s3_lib.c  s3_enc.c record/rec_layer_s3.c \
	s3_both.c s3_cbc.c s3_msg.c \
	t1_meth.c   t1_srvr.c t1_clnt.c  t1_lib.c  t1_enc.c t1_ext.c \
	d1_meth.c   d1_srvr.c d1_clnt.c  d1_lib.c  record/rec_layer_d1.c d1_msg.c \
	d1_both.c d1_srtp.c \
	ssl_lib.c ssl_err2.c ssl_cert.c ssl_sess.c \
	ssl_ciph.c ssl_stat.c ssl_rsa.c \
	ssl_asn1.c ssl_txt.c ssl_algs.c ssl_conf.c \
	bio_ssl.c ssl_err.c t1_reneg.c tls_srp.c t1_trce.c ssl_utst.c \
	record/ssl3_buffer.c record/ssl3_record.c record/dtls1_bitmap.c
LIBOBJ= \
	s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o record/rec_layer_s3.o \
	s3_both.o s3_cbc.o s3_msg.o \
	t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o t1_ext.o \
	d1_meth.o   d1_srvr.o d1_clnt.o  d1_lib.o  record/rec_layer_d1.o d1_msg.o \
	d1_both.o d1_srtp.o\
	ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o \
	ssl_ciph.o ssl_stat.o ssl_rsa.o \
	ssl_asn1.o ssl_txt.o ssl_algs.o ssl_conf.o \
	bio_ssl.o ssl_err.o t1_reneg.o tls_srp.o t1_trce.o ssl_utst.o \
	record/ssl3_buffer.o record/ssl3_record.o record/dtls1_bitmap.o

SRC= $(LIBSRC)

HEADER=	ssl_locl.h record/record_locl.h record/record.h

ALL=	$(GENERAL) $(SRC) $(HEADER)

# BSD make and GNU make disagree on where output goes
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

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

update: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f $(LIBOBJ) *.obj lib tags core .pure .nfs* *.old *.bak fluff
	rm -f record/*.obj record/lib record/retags record/core \
	record/.pure record/.nfs* record/*.old record/*.bak record/fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

bio_ssl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
bio_ssl.o: ../include/openssl/bn.h ../include/openssl/buffer.h
bio_ssl.o: ../include/openssl/comp.h ../include/openssl/crypto.h
bio_ssl.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
bio_ssl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
bio_ssl.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
bio_ssl.o: ../include/openssl/err.h ../include/openssl/evp.h
bio_ssl.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
bio_ssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
bio_ssl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
bio_ssl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
bio_ssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
bio_ssl.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
bio_ssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
bio_ssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
bio_ssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
bio_ssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
bio_ssl.o: ../include/openssl/tls1.h ../include/openssl/x509.h
bio_ssl.o: ../include/openssl/x509_vfy.h bio_ssl.c packet_locl.h
bio_ssl.o: record/record.h ssl_locl.h
d1_both.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_both.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_both.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_both.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
d1_both.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
d1_both.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
d1_both.o: ../include/openssl/err.h ../include/openssl/evp.h
d1_both.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
d1_both.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_both.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_both.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_both.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_both.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
d1_both.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
d1_both.o: ../include/openssl/sha.h ../include/openssl/srtp.h
d1_both.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
d1_both.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_both.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_both.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_both.c
d1_both.o: packet_locl.h record/record.h ssl_locl.h
d1_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_clnt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_clnt.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_clnt.o: ../include/openssl/dh.h ../include/openssl/dsa.h
d1_clnt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_clnt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_clnt.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_clnt.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_clnt.o: ../include/openssl/lhash.h ../include/openssl/md5.h
d1_clnt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_clnt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_clnt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
d1_clnt.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
d1_clnt.o: ../include/openssl/sha.h ../include/openssl/srtp.h
d1_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
d1_clnt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_clnt.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_clnt.c
d1_clnt.o: packet_locl.h record/record.h ssl_locl.h
d1_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_lib.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_lib.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_lib.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
d1_lib.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
d1_lib.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
d1_lib.o: ../include/openssl/err.h ../include/openssl/evp.h
d1_lib.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
d1_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_lib.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_lib.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
d1_lib.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
d1_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_lib.o: ../include/openssl/x509_vfy.h d1_lib.c packet_locl.h record/record.h
d1_lib.o: ssl_locl.h
d1_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_meth.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_meth.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_meth.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
d1_meth.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
d1_meth.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
d1_meth.o: ../include/openssl/err.h ../include/openssl/evp.h
d1_meth.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
d1_meth.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_meth.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_meth.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_meth.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_meth.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
d1_meth.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
d1_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_meth.o: ../include/openssl/x509_vfy.h d1_meth.c packet_locl.h
d1_meth.o: record/record.h ssl_locl.h
d1_msg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_msg.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_msg.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_msg.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
d1_msg.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
d1_msg.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
d1_msg.o: ../include/openssl/err.h ../include/openssl/evp.h
d1_msg.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
d1_msg.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_msg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_msg.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_msg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_msg.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_msg.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_msg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_msg.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
d1_msg.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
d1_msg.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_msg.o: ../include/openssl/x509_vfy.h d1_msg.c packet_locl.h record/record.h
d1_msg.o: ssl_locl.h
d1_srtp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_srtp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_srtp.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_srtp.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
d1_srtp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
d1_srtp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
d1_srtp.o: ../include/openssl/err.h ../include/openssl/evp.h
d1_srtp.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
d1_srtp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_srtp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_srtp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_srtp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_srtp.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
d1_srtp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
d1_srtp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_srtp.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
d1_srtp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
d1_srtp.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_srtp.o: ../include/openssl/x509_vfy.h d1_srtp.c packet_locl.h
d1_srtp.o: record/record.h ssl_locl.h
d1_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_srvr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
d1_srvr.o: ../include/openssl/comp.h ../include/openssl/crypto.h
d1_srvr.o: ../include/openssl/dh.h ../include/openssl/dsa.h
d1_srvr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
d1_srvr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
d1_srvr.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
d1_srvr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
d1_srvr.o: ../include/openssl/lhash.h ../include/openssl/md5.h
d1_srvr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_srvr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
d1_srvr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
d1_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
d1_srvr.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
d1_srvr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
d1_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
d1_srvr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_srvr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
d1_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_srvr.c
d1_srvr.o: packet_locl.h record/record.h ssl_locl.h
record/dtls1_bitmap.o: ../e_os.h ../include/openssl/asn1.h
record/dtls1_bitmap.o: ../include/openssl/bio.h ../include/openssl/bn.h
record/dtls1_bitmap.o: ../include/openssl/buffer.h ../include/openssl/comp.h
record/dtls1_bitmap.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
record/dtls1_bitmap.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
record/dtls1_bitmap.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
record/dtls1_bitmap.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
record/dtls1_bitmap.o: ../include/openssl/evp.h ../include/openssl/hmac.h
record/dtls1_bitmap.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
record/dtls1_bitmap.o: ../include/openssl/objects.h
record/dtls1_bitmap.o: ../include/openssl/opensslconf.h
record/dtls1_bitmap.o: ../include/openssl/opensslv.h
record/dtls1_bitmap.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
record/dtls1_bitmap.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
record/dtls1_bitmap.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
record/dtls1_bitmap.o: ../include/openssl/safestack.h ../include/openssl/sha.h
record/dtls1_bitmap.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
record/dtls1_bitmap.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
record/dtls1_bitmap.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
record/dtls1_bitmap.o: ../include/openssl/tls1.h ../include/openssl/x509.h
record/dtls1_bitmap.o: ../include/openssl/x509_vfy.h record/../packet_locl.h
record/dtls1_bitmap.o: record/../record/record.h record/../ssl_locl.h
record/dtls1_bitmap.o: record/dtls1_bitmap.c record/record_locl.h
record/rec_layer_d1.o: ../e_os.h ../include/openssl/asn1.h
record/rec_layer_d1.o: ../include/openssl/bio.h ../include/openssl/bn.h
record/rec_layer_d1.o: ../include/openssl/buffer.h ../include/openssl/comp.h
record/rec_layer_d1.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
record/rec_layer_d1.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
record/rec_layer_d1.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
record/rec_layer_d1.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
record/rec_layer_d1.o: ../include/openssl/evp.h ../include/openssl/hmac.h
record/rec_layer_d1.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
record/rec_layer_d1.o: ../include/openssl/objects.h
record/rec_layer_d1.o: ../include/openssl/opensslconf.h
record/rec_layer_d1.o: ../include/openssl/opensslv.h
record/rec_layer_d1.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
record/rec_layer_d1.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
record/rec_layer_d1.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
record/rec_layer_d1.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
record/rec_layer_d1.o: ../include/openssl/sha.h ../include/openssl/srtp.h
record/rec_layer_d1.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
record/rec_layer_d1.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
record/rec_layer_d1.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
record/rec_layer_d1.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
record/rec_layer_d1.o: record/../packet_locl.h record/../record/record.h
record/rec_layer_d1.o: record/../ssl_locl.h record/rec_layer_d1.c
record/rec_layer_d1.o: record/record_locl.h
record/rec_layer_s3.o: ../e_os.h ../include/openssl/asn1.h
record/rec_layer_s3.o: ../include/openssl/bio.h ../include/openssl/bn.h
record/rec_layer_s3.o: ../include/openssl/buffer.h ../include/openssl/comp.h
record/rec_layer_s3.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
record/rec_layer_s3.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
record/rec_layer_s3.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
record/rec_layer_s3.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
record/rec_layer_s3.o: ../include/openssl/evp.h ../include/openssl/hmac.h
record/rec_layer_s3.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
record/rec_layer_s3.o: ../include/openssl/objects.h
record/rec_layer_s3.o: ../include/openssl/opensslconf.h
record/rec_layer_s3.o: ../include/openssl/opensslv.h
record/rec_layer_s3.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
record/rec_layer_s3.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
record/rec_layer_s3.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
record/rec_layer_s3.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
record/rec_layer_s3.o: ../include/openssl/sha.h ../include/openssl/srtp.h
record/rec_layer_s3.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
record/rec_layer_s3.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
record/rec_layer_s3.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
record/rec_layer_s3.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
record/rec_layer_s3.o: record/../packet_locl.h record/../record/record.h
record/rec_layer_s3.o: record/../ssl_locl.h record/rec_layer_s3.c
record/rec_layer_s3.o: record/record_locl.h
record/ssl3_buffer.o: ../e_os.h ../include/openssl/asn1.h
record/ssl3_buffer.o: ../include/openssl/bio.h ../include/openssl/bn.h
record/ssl3_buffer.o: ../include/openssl/buffer.h ../include/openssl/comp.h
record/ssl3_buffer.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
record/ssl3_buffer.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
record/ssl3_buffer.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
record/ssl3_buffer.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
record/ssl3_buffer.o: ../include/openssl/evp.h ../include/openssl/hmac.h
record/ssl3_buffer.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
record/ssl3_buffer.o: ../include/openssl/objects.h
record/ssl3_buffer.o: ../include/openssl/opensslconf.h
record/ssl3_buffer.o: ../include/openssl/opensslv.h
record/ssl3_buffer.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
record/ssl3_buffer.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
record/ssl3_buffer.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
record/ssl3_buffer.o: ../include/openssl/safestack.h ../include/openssl/sha.h
record/ssl3_buffer.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
record/ssl3_buffer.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
record/ssl3_buffer.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
record/ssl3_buffer.o: ../include/openssl/tls1.h ../include/openssl/x509.h
record/ssl3_buffer.o: ../include/openssl/x509_vfy.h record/../packet_locl.h
record/ssl3_buffer.o: record/../record/record.h record/../ssl_locl.h
record/ssl3_buffer.o: record/record_locl.h record/ssl3_buffer.c
record/ssl3_record.o: ../e_os.h ../include/internal/constant_time_locl.h
record/ssl3_record.o: ../include/openssl/asn1.h ../include/openssl/bio.h
record/ssl3_record.o: ../include/openssl/bn.h ../include/openssl/buffer.h
record/ssl3_record.o: ../include/openssl/comp.h ../include/openssl/crypto.h
record/ssl3_record.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
record/ssl3_record.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
record/ssl3_record.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
record/ssl3_record.o: ../include/openssl/err.h ../include/openssl/evp.h
record/ssl3_record.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
record/ssl3_record.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
record/ssl3_record.o: ../include/openssl/opensslconf.h
record/ssl3_record.o: ../include/openssl/opensslv.h
record/ssl3_record.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
record/ssl3_record.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
record/ssl3_record.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
record/ssl3_record.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
record/ssl3_record.o: ../include/openssl/sha.h ../include/openssl/srtp.h
record/ssl3_record.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
record/ssl3_record.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
record/ssl3_record.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
record/ssl3_record.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
record/ssl3_record.o: record/../packet_locl.h record/../record/record.h
record/ssl3_record.o: record/../ssl_locl.h record/record_locl.h
record/ssl3_record.o: record/ssl3_record.c
s3_both.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_both.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_both.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_both.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_both.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_both.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_both.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_both.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s3_both.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_both.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_both.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_both.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_both.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_both.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_both.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_both.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_both.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_both.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_both.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s3_both.o: packet_locl.h record/record.h s3_both.c ssl_locl.h
s3_cbc.o: ../e_os.h ../include/internal/constant_time_locl.h
s3_cbc.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s3_cbc.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_cbc.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_cbc.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_cbc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_cbc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_cbc.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_cbc.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s3_cbc.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_cbc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s3_cbc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s3_cbc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_cbc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_cbc.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_cbc.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_cbc.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_cbc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_cbc.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_cbc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h packet_locl.h
s3_cbc.o: record/record.h s3_cbc.c ssl_locl.h
s3_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_clnt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_clnt.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_clnt.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s3_clnt.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_clnt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_clnt.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s3_clnt.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_clnt.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s3_clnt.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_clnt.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s3_clnt.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s3_clnt.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_clnt.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_clnt.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s3_clnt.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_clnt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_clnt.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s3_clnt.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s3_clnt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_clnt.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
s3_clnt.o: s3_clnt.c ssl_locl.h
s3_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_enc.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_enc.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_enc.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_enc.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_enc.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s3_enc.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s3_enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s3_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_enc.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_enc.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_enc.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_enc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_enc.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h packet_locl.h
s3_enc.o: record/record.h s3_enc.c ssl_locl.h
s3_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_lib.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_lib.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_lib.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s3_lib.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_lib.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_lib.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s3_lib.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s3_lib.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_lib.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_lib.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_lib.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_lib.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_lib.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h packet_locl.h
s3_lib.o: record/record.h s3_lib.c ssl_locl.h
s3_msg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_msg.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_msg.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_msg.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s3_msg.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s3_msg.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s3_msg.o: ../include/openssl/err.h ../include/openssl/evp.h
s3_msg.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s3_msg.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_msg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_msg.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_msg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_msg.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
s3_msg.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s3_msg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_msg.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s3_msg.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s3_msg.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_msg.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h s3_msg.c
s3_msg.o: ssl_locl.h
s3_srvr.o: ../e_os.h ../include/internal/constant_time_locl.h
s3_srvr.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s3_srvr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
s3_srvr.o: ../include/openssl/comp.h ../include/openssl/crypto.h
s3_srvr.o: ../include/openssl/dh.h ../include/openssl/dsa.h
s3_srvr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s3_srvr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s3_srvr.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s3_srvr.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s3_srvr.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_srvr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_srvr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s3_srvr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s3_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_srvr.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s3_srvr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s3_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_srvr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_srvr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s3_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s3_srvr.o: packet_locl.h record/record.h s3_srvr.c ssl_locl.h
ssl_algs.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_algs.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_algs.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_algs.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_algs.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_algs.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_algs.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_algs.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_algs.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_algs.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_algs.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_algs.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_algs.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_algs.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_algs.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_algs.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_algs.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_algs.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_algs.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_algs.o: ssl_algs.c ssl_locl.h
ssl_asn1.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/asn1t.h
ssl_asn1.o: ../include/openssl/bio.h ../include/openssl/bn.h
ssl_asn1.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_asn1.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
ssl_asn1.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_asn1.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_asn1.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_asn1.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_asn1.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_asn1.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_asn1.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_asn1.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_asn1.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_asn1.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_asn1.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_asn1.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_asn1.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_asn1.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_asn1.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_asn1.o: packet_locl.h record/record.h ssl_asn1.c ssl_locl.h
ssl_cert.o: ../e_os.h ../include/internal/o_dir.h ../include/openssl/asn1.h
ssl_cert.o: ../include/openssl/bio.h ../include/openssl/bn.h
ssl_cert.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_cert.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ssl_cert.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ssl_cert.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ssl_cert.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ssl_cert.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ssl_cert.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_cert.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_cert.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_cert.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_cert.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_cert.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_cert.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_cert.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_cert.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_cert.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_cert.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_cert.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_cert.o: ../include/openssl/x509v3.h packet_locl.h record/record.h
ssl_cert.o: ssl_cert.c ssl_locl.h
ssl_ciph.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_ciph.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_ciph.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_ciph.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_ciph.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_ciph.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_ciph.o: ../include/openssl/engine.h ../include/openssl/err.h
ssl_ciph.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_ciph.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_ciph.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_ciph.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_ciph.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_ciph.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_ciph.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_ciph.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_ciph.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_ciph.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_ciph.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_ciph.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_ciph.o: packet_locl.h record/record.h ssl_ciph.c ssl_locl.h
ssl_conf.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_conf.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_conf.o: ../include/openssl/comp.h ../include/openssl/conf.h
ssl_conf.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ssl_conf.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_conf.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_conf.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_conf.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_conf.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_conf.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_conf.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_conf.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_conf.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_conf.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_conf.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_conf.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_conf.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_conf.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_conf.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_conf.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_conf.o: ssl_conf.c ssl_locl.h
ssl_err.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_err.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_err.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ssl_err.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_err.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_err.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_err.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_err.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_err.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_err.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_err.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_err.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_err.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_err.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_err.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_err.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_err.o: ../include/openssl/x509_vfy.h ssl_err.c
ssl_err2.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_err2.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ssl_err2.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ssl_err2.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_err2.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_err2.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_err2.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_err2.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_err2.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_err2.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_err2.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_err2.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_err2.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_err2.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_err2.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_err2.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_err2.o: ../include/openssl/x509_vfy.h ssl_err2.c
ssl_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_lib.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_lib.o: ../include/openssl/comp.h ../include/openssl/conf.h
ssl_lib.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ssl_lib.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_lib.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_lib.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_lib.o: ../include/openssl/engine.h ../include/openssl/err.h
ssl_lib.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_lib.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_lib.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ssl_lib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_lib.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_lib.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
ssl_lib.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ssl_lib.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ssl_lib.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_lib.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ssl_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ssl_lib.o: ../include/openssl/x509v3.h packet_locl.h record/record.h ssl_lib.c
ssl_lib.o: ssl_locl.h
ssl_rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_rsa.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_rsa.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_rsa.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_rsa.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_rsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_rsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_rsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_rsa.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_rsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_rsa.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_rsa.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_rsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_rsa.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_rsa.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_rsa.o: ssl_locl.h ssl_rsa.c
ssl_sess.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_sess.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_sess.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_sess.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_sess.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_sess.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_sess.o: ../include/openssl/engine.h ../include/openssl/err.h
ssl_sess.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ssl_sess.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_sess.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ssl_sess.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ssl_sess.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_sess.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_sess.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ssl_sess.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_sess.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_sess.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_sess.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_sess.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_sess.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_sess.o: ssl_locl.h ssl_sess.c
ssl_stat.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_stat.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_stat.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_stat.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_stat.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_stat.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_stat.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_stat.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_stat.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_stat.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_stat.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_stat.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_stat.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_stat.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_stat.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_stat.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_stat.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_stat.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_stat.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_stat.o: ssl_locl.h ssl_stat.c
ssl_txt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_txt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_txt.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_txt.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_txt.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_txt.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_txt.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_txt.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_txt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_txt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_txt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_txt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_txt.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_txt.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_txt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_txt.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_txt.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_txt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_txt.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_txt.o: ssl_locl.h ssl_txt.c
ssl_utst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_utst.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ssl_utst.o: ../include/openssl/comp.h ../include/openssl/crypto.h
ssl_utst.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
ssl_utst.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ssl_utst.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ssl_utst.o: ../include/openssl/err.h ../include/openssl/evp.h
ssl_utst.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ssl_utst.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_utst.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ssl_utst.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ssl_utst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_utst.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
ssl_utst.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ssl_utst.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_utst.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ssl_utst.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ssl_utst.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_utst.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
ssl_utst.o: ssl_locl.h ssl_utst.c
t1_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_clnt.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_clnt.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_clnt.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_clnt.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_clnt.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_clnt.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_clnt.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_clnt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_clnt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_clnt.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_clnt.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
t1_clnt.o: ../include/openssl/sha.h ../include/openssl/srtp.h
t1_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_clnt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_clnt.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_clnt.o: packet_locl.h record/record.h ssl_locl.h t1_clnt.c
t1_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_enc.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_enc.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_enc.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_enc.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_enc.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_enc.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
t1_enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
t1_enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
t1_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
t1_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
t1_enc.o: ../include/openssl/rand.h ../include/openssl/rsa.h
t1_enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_enc.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_enc.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
t1_enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_enc.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_enc.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
t1_enc.o: ssl_locl.h t1_enc.c
t1_ext.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_ext.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_ext.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_ext.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_ext.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_ext.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_ext.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_ext.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_ext.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_ext.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_ext.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_ext.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_ext.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_ext.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_ext.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_ext.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
t1_ext.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_ext.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_ext.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
t1_ext.o: ssl_locl.h t1_ext.c
t1_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_lib.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_lib.o: ../include/openssl/comp.h ../include/openssl/conf.h
t1_lib.o: ../include/openssl/crypto.h ../include/openssl/dh.h
t1_lib.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_lib.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_lib.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_lib.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_lib.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_lib.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
t1_lib.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
t1_lib.o: ../include/openssl/pem.h ../include/openssl/pem2.h
t1_lib.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
t1_lib.o: ../include/openssl/rand.h ../include/openssl/rsa.h
t1_lib.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
t1_lib.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_lib.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
t1_lib.o: packet_locl.h record/record.h ssl_locl.h t1_lib.c
t1_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_meth.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_meth.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_meth.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_meth.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_meth.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_meth.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_meth.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_meth.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_meth.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_meth.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_meth.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_meth.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
t1_meth.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_meth.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
t1_meth.o: ssl_locl.h t1_meth.c
t1_reneg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_reneg.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_reneg.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_reneg.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_reneg.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_reneg.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_reneg.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_reneg.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_reneg.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_reneg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_reneg.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_reneg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_reneg.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_reneg.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_reneg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_reneg.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
t1_reneg.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_reneg.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_reneg.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
t1_reneg.o: ssl_locl.h t1_reneg.c
t1_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_srvr.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_srvr.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_srvr.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_srvr.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_srvr.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_srvr.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_srvr.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_srvr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_srvr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_srvr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_srvr.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
t1_srvr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
t1_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_srvr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_srvr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
t1_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_srvr.o: packet_locl.h record/record.h ssl_locl.h t1_srvr.c
t1_trce.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_trce.o: ../include/openssl/bn.h ../include/openssl/buffer.h
t1_trce.o: ../include/openssl/comp.h ../include/openssl/crypto.h
t1_trce.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
t1_trce.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
t1_trce.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
t1_trce.o: ../include/openssl/err.h ../include/openssl/evp.h
t1_trce.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
t1_trce.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_trce.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
t1_trce.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
t1_trce.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_trce.o: ../include/openssl/pqueue.h ../include/openssl/rsa.h
t1_trce.o: ../include/openssl/safestack.h ../include/openssl/sha.h
t1_trce.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_trce.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
t1_trce.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
t1_trce.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_trce.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
t1_trce.o: ssl_locl.h t1_trce.c
tls_srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
tls_srp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
tls_srp.o: ../include/openssl/comp.h ../include/openssl/crypto.h
tls_srp.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
tls_srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
tls_srp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
tls_srp.o: ../include/openssl/err.h ../include/openssl/evp.h
tls_srp.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
tls_srp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
tls_srp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
tls_srp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
tls_srp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
tls_srp.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
tls_srp.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
tls_srp.o: ../include/openssl/sha.h ../include/openssl/srp.h
tls_srp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
tls_srp.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
tls_srp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
tls_srp.o: ../include/openssl/tls1.h ../include/openssl/x509.h
tls_srp.o: ../include/openssl/x509_vfy.h packet_locl.h record/record.h
tls_srp.o: ssl_locl.h tls_srp.c
