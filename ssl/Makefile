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
TEST=ssltest.c
APPS=

LIB=$(TOP)/libssl.a
SHARED_LIB= libssl$(SHLIB_EXT)
LIBSRC=	\
	s2_meth.c   s2_srvr.c s2_clnt.c  s2_lib.c  s2_enc.c s2_pkt.c \
	s3_meth.c   s3_srvr.c s3_clnt.c  s3_lib.c  s3_enc.c s3_pkt.c s3_both.c s3_cbc.c \
	s23_meth.c s23_srvr.c s23_clnt.c s23_lib.c          s23_pkt.c \
	t1_meth.c   t1_srvr.c t1_clnt.c  t1_lib.c  t1_enc.c \
	d1_meth.c   d1_srvr.c d1_clnt.c  d1_lib.c  d1_pkt.c \
	d1_both.c d1_enc.c d1_srtp.c \
	ssl_lib.c ssl_err2.c ssl_cert.c ssl_sess.c \
	ssl_ciph.c ssl_stat.c ssl_rsa.c \
	ssl_asn1.c ssl_txt.c ssl_algs.c \
	bio_ssl.c ssl_err.c kssl.c tls_srp.c t1_reneg.c
LIBOBJ= \
	s2_meth.o  s2_srvr.o  s2_clnt.o  s2_lib.o  s2_enc.o s2_pkt.o \
	s3_meth.o  s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o s3_pkt.o s3_both.o s3_cbc.o \
	s23_meth.o s23_srvr.o s23_clnt.o s23_lib.o          s23_pkt.o \
	t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o \
	d1_meth.o   d1_srvr.o d1_clnt.o  d1_lib.o  d1_pkt.o \
	d1_both.o d1_enc.o d1_srtp.o\
	ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o \
	ssl_ciph.o ssl_stat.o ssl_rsa.o \
	ssl_asn1.o ssl_txt.o ssl_algs.o \
	bio_ssl.o ssl_err.o kssl.o tls_srp.o t1_reneg.o

SRC= $(LIBSRC)

EXHEADER= ssl.h ssl2.h ssl3.h ssl23.h tls1.h dtls1.h kssl.h srtp.h
HEADER=	$(EXHEADER) ssl_locl.h kssl_lcl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

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

links:
	@$(PERL) $(TOP)/util/mklink.pl ../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../apps $(APPS)

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
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

bio_ssl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
bio_ssl.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
bio_ssl.o: ../include/openssl/err.h ../include/openssl/kssl.h
bio_ssl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
bio_ssl.o: ../include/openssl/objects.h ../include/openssl/pem.h
bio_ssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
bio_ssl.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
bio_ssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
bio_ssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
bio_ssl.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
bio_ssl.o: ../include/openssl/tls1.h ../include/openssl/x509.h
bio_ssl.o: ../include/openssl/x509_vfy.h bio_ssl.c
d1_both.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_both.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_both.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_both.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
d1_both.o: ../include/openssl/objects.h ../include/openssl/pem.h
d1_both.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_both.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
d1_both.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
d1_both.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
d1_both.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
d1_both.o: ../include/openssl/stack.h ../include/openssl/tls1.h
d1_both.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_both.c
d1_both.o: ssl_locl.h
d1_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_clnt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_clnt.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_clnt.o: ../include/openssl/lhash.h ../include/openssl/md5.h
d1_clnt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_clnt.o: ../include/openssl/pem.h ../include/openssl/pem2.h
d1_clnt.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
d1_clnt.o: ../include/openssl/rand.h ../include/openssl/safestack.h
d1_clnt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_clnt.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_clnt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_clnt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_clnt.o: ../include/openssl/x509_vfy.h d1_clnt.c kssl_lcl.h ssl_locl.h
d1_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_enc.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_enc.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_enc.o: ../include/openssl/lhash.h ../include/openssl/md5.h
d1_enc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
d1_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
d1_enc.o: ../include/openssl/rand.h ../include/openssl/safestack.h
d1_enc.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_enc.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_enc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_enc.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_enc.o: ../include/openssl/x509_vfy.h d1_enc.c ssl_locl.h
d1_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_lib.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_lib.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_lib.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
d1_lib.o: ../include/openssl/objects.h ../include/openssl/pem.h
d1_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_lib.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
d1_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_lib.o: ../include/openssl/x509_vfy.h d1_lib.c ssl_locl.h
d1_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_meth.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_meth.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_meth.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
d1_meth.o: ../include/openssl/objects.h ../include/openssl/pem.h
d1_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_meth.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
d1_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_meth.o: ../include/openssl/x509_vfy.h d1_meth.c ssl_locl.h
d1_pkt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_pkt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_pkt.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_pkt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
d1_pkt.o: ../include/openssl/objects.h ../include/openssl/pem.h
d1_pkt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_pkt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
d1_pkt.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
d1_pkt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
d1_pkt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
d1_pkt.o: ../include/openssl/stack.h ../include/openssl/tls1.h
d1_pkt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h d1_pkt.c
d1_pkt.o: ssl_locl.h
d1_srtp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_srtp.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_srtp.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_srtp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
d1_srtp.o: ../include/openssl/objects.h ../include/openssl/pem.h
d1_srtp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
d1_srtp.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
d1_srtp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_srtp.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_srtp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_srtp.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_srtp.o: ../include/openssl/x509_vfy.h d1_srtp.c srtp.h ssl_locl.h
d1_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
d1_srvr.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
d1_srvr.o: ../include/openssl/err.h ../include/openssl/kssl.h
d1_srvr.o: ../include/openssl/lhash.h ../include/openssl/md5.h
d1_srvr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
d1_srvr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
d1_srvr.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
d1_srvr.o: ../include/openssl/rand.h ../include/openssl/safestack.h
d1_srvr.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
d1_srvr.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
d1_srvr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
d1_srvr.o: ../include/openssl/tls1.h ../include/openssl/x509.h
d1_srvr.o: ../include/openssl/x509_vfy.h d1_srvr.c ssl_locl.h
kssl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
kssl.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
kssl.o: ../include/openssl/krb5_asn.h ../include/openssl/kssl.h
kssl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
kssl.o: ../include/openssl/objects.h ../include/openssl/pem.h
kssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
kssl.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
kssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
kssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
kssl.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
kssl.o: ../include/openssl/tls1.h ../include/openssl/x509.h
kssl.o: ../include/openssl/x509_vfy.h kssl.c kssl_lcl.h
s23_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_clnt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s23_clnt.o: ../include/openssl/err.h ../include/openssl/kssl.h
s23_clnt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s23_clnt.o: ../include/openssl/objects.h ../include/openssl/pem.h
s23_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s23_clnt.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s23_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s23_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s23_clnt.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s23_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s23_clnt.c
s23_clnt.o: ssl_locl.h
s23_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_lib.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s23_lib.o: ../include/openssl/err.h ../include/openssl/kssl.h
s23_lib.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s23_lib.o: ../include/openssl/objects.h ../include/openssl/pem.h
s23_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_lib.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s23_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s23_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s23_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s23_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s23_lib.o: ../include/openssl/x509_vfy.h s23_lib.c ssl_locl.h
s23_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_meth.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s23_meth.o: ../include/openssl/err.h ../include/openssl/kssl.h
s23_meth.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s23_meth.o: ../include/openssl/objects.h ../include/openssl/pem.h
s23_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_meth.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s23_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s23_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s23_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s23_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s23_meth.o: ../include/openssl/x509_vfy.h s23_meth.c ssl_locl.h
s23_pkt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_pkt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s23_pkt.o: ../include/openssl/err.h ../include/openssl/kssl.h
s23_pkt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s23_pkt.o: ../include/openssl/objects.h ../include/openssl/pem.h
s23_pkt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_pkt.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s23_pkt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s23_pkt.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s23_pkt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s23_pkt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s23_pkt.o: ../include/openssl/x509_vfy.h s23_pkt.c ssl_locl.h
s23_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s23_srvr.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s23_srvr.o: ../include/openssl/err.h ../include/openssl/kssl.h
s23_srvr.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s23_srvr.o: ../include/openssl/objects.h ../include/openssl/pem.h
s23_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s23_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s23_srvr.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s23_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s23_srvr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s23_srvr.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s23_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s23_srvr.c
s23_srvr.o: ssl_locl.h
s2_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s2_clnt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s2_clnt.o: ../include/openssl/err.h ../include/openssl/kssl.h
s2_clnt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s2_clnt.o: ../include/openssl/objects.h ../include/openssl/pem.h
s2_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s2_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s2_clnt.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s2_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s2_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s2_clnt.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s2_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s2_clnt.c
s2_clnt.o: ssl_locl.h
s2_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s2_enc.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s2_enc.o: ../include/openssl/err.h ../include/openssl/kssl.h
s2_enc.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s2_enc.o: ../include/openssl/objects.h ../include/openssl/pem.h
s2_enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s2_enc.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s2_enc.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s2_enc.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s2_enc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s2_enc.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s2_enc.o: ../include/openssl/x509_vfy.h s2_enc.c ssl_locl.h
s2_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s2_lib.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s2_lib.o: ../include/openssl/err.h ../include/openssl/kssl.h
s2_lib.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s2_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s2_lib.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s2_lib.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s2_lib.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s2_lib.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s2_lib.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s2_lib.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s2_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s2_lib.c
s2_lib.o: ssl_locl.h
s2_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s2_meth.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s2_meth.o: ../include/openssl/err.h ../include/openssl/kssl.h
s2_meth.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s2_meth.o: ../include/openssl/objects.h ../include/openssl/pem.h
s2_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s2_meth.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s2_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s2_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s2_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s2_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s2_meth.o: ../include/openssl/x509_vfy.h s2_meth.c ssl_locl.h
s2_pkt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s2_pkt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s2_pkt.o: ../include/openssl/err.h ../include/openssl/kssl.h
s2_pkt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s2_pkt.o: ../include/openssl/objects.h ../include/openssl/pem.h
s2_pkt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s2_pkt.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s2_pkt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s2_pkt.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s2_pkt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s2_pkt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s2_pkt.o: ../include/openssl/x509_vfy.h s2_pkt.c ssl_locl.h
s2_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s2_srvr.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s2_srvr.o: ../include/openssl/err.h ../include/openssl/kssl.h
s2_srvr.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s2_srvr.o: ../include/openssl/objects.h ../include/openssl/pem.h
s2_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s2_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s2_srvr.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s2_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s2_srvr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s2_srvr.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s2_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s2_srvr.c
s2_srvr.o: ssl_locl.h
s3_both.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_both.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_both.o: ../include/openssl/err.h ../include/openssl/kssl.h
s3_both.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s3_both.o: ../include/openssl/objects.h ../include/openssl/pem.h
s3_both.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_both.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_both.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s3_both.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_both.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_both.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s3_both.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s3_both.c
s3_both.o: ssl_locl.h
s3_cbc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_cbc.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_cbc.o: ../include/openssl/err.h ../include/openssl/kssl.h
s3_cbc.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_cbc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_cbc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_cbc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_cbc.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s3_cbc.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_cbc.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_cbc.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s3_cbc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s3_cbc.c
s3_cbc.o: ssl_locl.h
s3_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_clnt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_clnt.o: ../include/openssl/engine.h ../include/openssl/err.h
s3_clnt.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_clnt.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_clnt.o: ../include/openssl/objects.h ../include/openssl/pem.h
s3_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_clnt.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s3_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_clnt.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s3_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h kssl_lcl.h
s3_clnt.o: s3_clnt.c ssl_locl.h
s3_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_enc.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_enc.o: ../include/openssl/err.h ../include/openssl/kssl.h
s3_enc.o: ../include/openssl/lhash.h ../include/openssl/md5.h
s3_enc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s3_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s3_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s3_enc.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s3_enc.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_enc.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_enc.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s3_enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s3_enc.c
s3_enc.o: ssl_locl.h
s3_lib.o: ../crypto/ec/ec_lcl.h ../e_os.h ../include/openssl/asn1.h
s3_lib.o: ../include/openssl/bio.h ../include/openssl/comp.h
s3_lib.o: ../include/openssl/dtls1.h ../include/openssl/err.h
s3_lib.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_lib.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_lib.o: ../include/openssl/objects.h ../include/openssl/pem.h
s3_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_lib.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s3_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_lib.o: ../include/openssl/x509_vfy.h kssl_lcl.h s3_lib.c ssl_locl.h
s3_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_meth.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_meth.o: ../include/openssl/err.h ../include/openssl/kssl.h
s3_meth.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s3_meth.o: ../include/openssl/objects.h ../include/openssl/pem.h
s3_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_meth.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s3_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s3_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s3_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s3_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
s3_meth.o: ../include/openssl/x509_vfy.h s3_meth.c ssl_locl.h
s3_pkt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_pkt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_pkt.o: ../include/openssl/err.h ../include/openssl/kssl.h
s3_pkt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s3_pkt.o: ../include/openssl/objects.h ../include/openssl/pem.h
s3_pkt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_pkt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_pkt.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s3_pkt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_pkt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_pkt.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s3_pkt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h s3_pkt.c
s3_pkt.o: ssl_locl.h
s3_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s3_srvr.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
s3_srvr.o: ../include/openssl/err.h ../include/openssl/krb5_asn.h
s3_srvr.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s3_srvr.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
s3_srvr.o: ../include/openssl/objects.h ../include/openssl/pem.h
s3_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s3_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s3_srvr.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
s3_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s3_srvr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s3_srvr.o: ../include/openssl/stack.h ../include/openssl/tls1.h
s3_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h kssl_lcl.h
s3_srvr.o: s3_srvr.c ssl_locl.h
ssl_algs.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_algs.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_algs.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_algs.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_algs.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_algs.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_algs.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_algs.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_algs.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_algs.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_algs.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_algs.o: ../include/openssl/x509_vfy.h ssl_algs.c ssl_locl.h
ssl_asn1.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/asn1_mac.h
ssl_asn1.o: ../include/openssl/bio.h ../include/openssl/comp.h
ssl_asn1.o: ../include/openssl/dtls1.h ../include/openssl/err.h
ssl_asn1.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_asn1.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_asn1.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_asn1.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_asn1.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
ssl_asn1.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_asn1.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_asn1.o: ../include/openssl/stack.h ../include/openssl/tls1.h
ssl_asn1.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h ssl_asn1.c
ssl_asn1.o: ssl_locl.h
ssl_cert.o: ../crypto/o_dir.h ../e_os.h ../include/openssl/asn1.h
ssl_cert.o: ../include/openssl/bio.h ../include/openssl/comp.h
ssl_cert.o: ../include/openssl/conf.h ../include/openssl/dtls1.h
ssl_cert.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_cert.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_cert.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_cert.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_cert.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_cert.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_cert.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_cert.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_cert.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_cert.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
ssl_cert.o: ssl_cert.c ssl_locl.h
ssl_ciph.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_ciph.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_ciph.o: ../include/openssl/engine.h ../include/openssl/err.h
ssl_ciph.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_ciph.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_ciph.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_ciph.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_ciph.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
ssl_ciph.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ssl_ciph.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ssl_ciph.o: ../include/openssl/stack.h ../include/openssl/tls1.h
ssl_ciph.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h ssl_ciph.c
ssl_ciph.o: ssl_locl.h
ssl_err.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_err.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_err.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_err.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_err.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_err.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_err.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_err.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_err.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_err.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_err.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_err.o: ../include/openssl/x509_vfy.h ssl_err.c
ssl_err2.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_err2.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_err2.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_err2.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_err2.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_err2.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_err2.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_err2.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_err2.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_err2.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_err2.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_err2.o: ../include/openssl/x509_vfy.h ssl_err2.c
ssl_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_lib.o: ../include/openssl/comp.h ../include/openssl/conf.h
ssl_lib.o: ../include/openssl/dtls1.h ../include/openssl/engine.h
ssl_lib.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_lib.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_lib.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ssl_lib.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_lib.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_lib.o: ../include/openssl/rand.h ../include/openssl/safestack.h
ssl_lib.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_lib.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_lib.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_lib.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_lib.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h kssl_lcl.h
ssl_lib.o: ssl_lib.c ssl_locl.h
ssl_rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_rsa.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_rsa.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_rsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_rsa.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_rsa.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_rsa.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_rsa.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_rsa.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_rsa.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_rsa.o: ../include/openssl/x509_vfy.h ssl_locl.h ssl_rsa.c
ssl_sess.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_sess.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_sess.o: ../include/openssl/engine.h ../include/openssl/err.h
ssl_sess.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ssl_sess.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ssl_sess.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ssl_sess.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ssl_sess.o: ../include/openssl/rand.h ../include/openssl/safestack.h
ssl_sess.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_sess.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_sess.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_sess.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_sess.o: ../include/openssl/x509_vfy.h ssl_locl.h ssl_sess.c
ssl_stat.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_stat.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_stat.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_stat.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_stat.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_stat.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_stat.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_stat.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_stat.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_stat.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_stat.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_stat.o: ../include/openssl/x509_vfy.h ssl_locl.h ssl_stat.c
ssl_txt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ssl_txt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
ssl_txt.o: ../include/openssl/err.h ../include/openssl/kssl.h
ssl_txt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ssl_txt.o: ../include/openssl/objects.h ../include/openssl/pem.h
ssl_txt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ssl_txt.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ssl_txt.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ssl_txt.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ssl_txt.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ssl_txt.o: ../include/openssl/tls1.h ../include/openssl/x509.h
ssl_txt.o: ../include/openssl/x509_vfy.h ssl_locl.h ssl_txt.c
t1_clnt.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_clnt.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
t1_clnt.o: ../include/openssl/err.h ../include/openssl/kssl.h
t1_clnt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
t1_clnt.o: ../include/openssl/objects.h ../include/openssl/pem.h
t1_clnt.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_clnt.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_clnt.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
t1_clnt.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_clnt.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
t1_clnt.o: ../include/openssl/stack.h ../include/openssl/tls1.h
t1_clnt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h ssl_locl.h
t1_clnt.o: t1_clnt.c
t1_enc.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_enc.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
t1_enc.o: ../include/openssl/err.h ../include/openssl/kssl.h
t1_enc.o: ../include/openssl/lhash.h ../include/openssl/md5.h
t1_enc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
t1_enc.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
t1_enc.o: ../include/openssl/rand.h ../include/openssl/safestack.h
t1_enc.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_enc.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_enc.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_enc.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_enc.o: ../include/openssl/x509_vfy.h ssl_locl.h t1_enc.c
t1_lib.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_lib.o: ../include/openssl/comp.h ../include/openssl/conf.h
t1_lib.o: ../include/openssl/dtls1.h ../include/openssl/err.h
t1_lib.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
t1_lib.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
t1_lib.o: ../include/openssl/ocsp.h ../include/openssl/pem.h
t1_lib.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_lib.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_lib.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
t1_lib.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_lib.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
t1_lib.o: ../include/openssl/stack.h ../include/openssl/tls1.h
t1_lib.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
t1_lib.o: ../include/openssl/x509v3.h ssl_locl.h t1_lib.c
t1_meth.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_meth.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
t1_meth.o: ../include/openssl/err.h ../include/openssl/kssl.h
t1_meth.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
t1_meth.o: ../include/openssl/objects.h ../include/openssl/pem.h
t1_meth.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_meth.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
t1_meth.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_meth.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_meth.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_meth.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_meth.o: ../include/openssl/x509_vfy.h ssl_locl.h t1_meth.c
t1_reneg.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_reneg.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
t1_reneg.o: ../include/openssl/err.h ../include/openssl/kssl.h
t1_reneg.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
t1_reneg.o: ../include/openssl/objects.h ../include/openssl/pem.h
t1_reneg.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_reneg.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
t1_reneg.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
t1_reneg.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
t1_reneg.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
t1_reneg.o: ../include/openssl/tls1.h ../include/openssl/x509.h
t1_reneg.o: ../include/openssl/x509_vfy.h ssl_locl.h t1_reneg.c
t1_srvr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
t1_srvr.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
t1_srvr.o: ../include/openssl/err.h ../include/openssl/kssl.h
t1_srvr.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
t1_srvr.o: ../include/openssl/objects.h ../include/openssl/pem.h
t1_srvr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
t1_srvr.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
t1_srvr.o: ../include/openssl/safestack.h ../include/openssl/srtp.h
t1_srvr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
t1_srvr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
t1_srvr.o: ../include/openssl/stack.h ../include/openssl/tls1.h
t1_srvr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h ssl_locl.h
t1_srvr.o: t1_srvr.c
tls_srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
tls_srp.o: ../include/openssl/comp.h ../include/openssl/dtls1.h
tls_srp.o: ../include/openssl/err.h ../include/openssl/kssl.h
tls_srp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
tls_srp.o: ../include/openssl/objects.h ../include/openssl/pem.h
tls_srp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
tls_srp.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
tls_srp.o: ../include/openssl/safestack.h ../include/openssl/srp.h
tls_srp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
tls_srp.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
tls_srp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
tls_srp.o: ../include/openssl/tls1.h ../include/openssl/x509.h
tls_srp.o: ../include/openssl/x509_vfy.h ssl_locl.h tls_srp.c
