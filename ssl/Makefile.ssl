#
# SSLeay/ssl/Makefile
#

DIR=	ssl
TOP=	..
CC=	cc
INCLUDES= -I../crypto -I../include
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	makedepend -f Makefile.ssl
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

ERR=ssl
ERRC=ssl_err
GENERAL=Makefile README
TEST=ssltest.c
APPS=

LIB=$(TOP)/libssl.a
LIBSRC=	\
	s2_meth.c   s2_srvr.c s2_clnt.c  s2_lib.c  s2_enc.c s2_pkt.c \
	s3_meth.c   s3_srvr.c s3_clnt.c  s3_lib.c  s3_enc.c s3_pkt.c s3_both.c \
	s23_meth.c s23_srvr.c s23_clnt.c s23_lib.c          s23_pkt.c \
	t1_meth.c   t1_srvr.c t1_clnt.c  t1_lib.c  t1_enc.c \
	ssl_lib.c ssl_err2.c ssl_cert.c ssl_sess.c \
	ssl_ciph.c ssl_stat.c ssl_rsa.c \
	ssl_asn1.c ssl_txt.c ssl_algs.c \
	bio_ssl.c $(ERRC).c
LIBOBJ= \
	s2_meth.o  s2_srvr.o  s2_clnt.o  s2_lib.o  s2_enc.o s2_pkt.o \
	s3_meth.o  s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o s3_pkt.o s3_both.o \
	s23_meth.o s23_srvr.o s23_clnt.o s23_lib.o          s23_pkt.o \
	t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o \
	ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o \
	ssl_ciph.o ssl_stat.o ssl_rsa.o \
	ssl_asn1.o ssl_txt.o ssl_algs.o \
	bio_ssl.o $(ERRC).o

SRC= $(LIBSRC)

EXHEADER= ssl.h ssl2.h ssl3.h ssl23.h tls1.h
HEADER=	$(EXHEADER) ssl_locl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	sh $(TOP)/util/ranlib.sh $(LIB)
	@touch lib

files:
	perl $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	/bin/rm -f Makefile
	$(TOP)/util/point.sh Makefile.ssl Makefile ;
	$(TOP)/util/mklink.sh ../include $(EXHEADER)
	$(TOP)/util/mklink.sh ../test $(TEST)
	$(TOP)/util/mklink.sh ../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALLTOP)/include/$$i; \
	chmod 644 $(INSTALLTOP)/include/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(PROGS) $(LIBSRC)

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	/bin/rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

errors:
	perl $(TOP)/util/err-ins.pl $(ERR).err $(ERR).h
	perl ../crypto/err/err_genc.pl -s $(ERR).h $(ERRC).c

# DO NOT DELETE THIS LINE -- make depend depends on it.
