#
# OpenSSL/ssl/Makefile
#

DIR_ssl=	ssl
INCLUDES_ssl= -I../crypto -I$(TOP_ssl) -I../include $(KRB5_INCLUDES)
# KRB5 stuff

CFLAGS_ssl= $(INCLUDES_ssl) $(CFLAG)

GENERAL_ssl=Makefile README ssl-lib.com install.com
TEST_ssl=ssltest.c heartbeat_test.c
APPS_ssl=

LIB_ssl=$(TOP_ssl)/libssl.a
SHARED_LIB_ssl= libssl$(SHLIB_EXT)
LIBSRC_ssl=	\
	s2_meth.c   s2_srvr.c s2_clnt.c  s2_lib.c  s2_enc.c s2_pkt.c \
	s3_meth.c   s3_srvr.c s3_clnt.c  s3_lib.c  s3_enc.c s3_pkt.c s3_both.c s3_cbc.c \
	s23_meth.c s23_srvr.c s23_clnt.c s23_lib.c          s23_pkt.c \
	t1_meth.c   t1_srvr.c t1_clnt.c  t1_lib.c  t1_enc.c t1_ext.c \
	d1_meth.c   d1_srvr.c d1_clnt.c  d1_lib.c  d1_pkt.c \
	d1_both.c d1_enc.c d1_srtp.c \
	ssl_lib.c ssl_err2.c ssl_cert.c ssl_sess.c \
	ssl_ciph.c ssl_stat.c ssl_rsa.c \
	ssl_asn1.c ssl_txt.c ssl_algs.c ssl_conf.c \
	bio_ssl.c ssl_err.c kssl.c t1_reneg.c tls_srp.c t1_trce.c ssl_utst.c
LIBOBJ_ssl= \
	s2_meth.o  s2_srvr.o  s2_clnt.o  s2_lib.o  s2_enc.o s2_pkt.o \
	s3_meth.o  s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o s3_pkt.o s3_both.o s3_cbc.o \
	s23_meth.o s23_srvr.o s23_clnt.o s23_lib.o          s23_pkt.o \
	t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o t1_ext.o \
	d1_meth.o   d1_srvr.o d1_clnt.o  d1_lib.o  d1_pkt.o \
	d1_both.o d1_enc.o d1_srtp.o\
	ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o \
	ssl_ciph.o ssl_stat.o ssl_rsa.o \
	ssl_asn1.o ssl_txt.o ssl_algs.o ssl_conf.o \
	bio_ssl.o ssl_err.o kssl.o t1_reneg.o tls_srp.o t1_trce.o ssl_utst.o

SRC_ssl= $(LIBSRC_ssl)

EXHEADER_ssl= ssl.h ssl2.h ssl3.h ssl23.h tls1.h dtls1.h kssl.h srtp.h
HEADER_ssl=	$(EXHEADER_ssl) ssl_locl.h kssl_lcl.h

ALL_ssl=    $(GENERAL_ssl) $(SRC_ssl) $(HEADER_ssl)

top: top_ssl
top_ssl:
	(cd ..; $(MAKE) DIRS=$(DIR_ssl) all)

all: all_ssl
all_ssl:	shared

lib:	$(LIBOBJ_ssl)
	$(AR) $(LIB_ssl) $(LIBOBJ_ssl)
	$(RANLIB) $(LIB_ssl) || echo Never mind.
	@touch lib

shared: shared_ssl
shared_ssl: lib
	if [ -n "$(SHARED_LIBS)" ]; then \
		(cd ..; $(MAKE) $(SHARED_LIB_ssl)); \
	fi

files: files_ssl
files_ssl:
	$(PERL) $(TOP_ssl)/util/files.pl TOP=$(TOP_ssl) Makefile >> $(TOP_ssl)/MINFO

links: links_ssl
links_ssl:
	@$(PERL) $(TOP_ssl)/util/mklink.pl ../include/openssl $(EXHEADER_ssl)
	@$(PERL) $(TOP_ssl)/util/mklink.pl ../test $(TEST_ssl)
	@$(PERL) $(TOP_ssl)/util/mklink.pl ../apps $(APPS_ssl)

install: install_ssl
install_ssl:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_ssl)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_ssl
tags_ssl:
	ctags $(SRC_ssl)

tests: tests_ssl
tests_ssl:

lint: lint_ssl
lint_ssl:
	lint -DLINT $(INCLUDES_ssl) $(SRC_ssl)>fluff

dclean: dclean_ssl
dclean_ssl:

clean: clean_ssl
clean_ssl:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_ssl) $(CPPFLAGS) -c -o $@ $<
