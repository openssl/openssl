#
# OpenSSL/ssl/Makefile
#

INCLUDES_ssl= -Icrypto -I. -Iinclude $(KRB5_INCLUDES)
# KRB5 stuff

CFLAGS_ssl= $(INCLUDES_ssl) $(CFLAG)

GENERAL_ssl=ssl/Makefile ssl/README ssl/ssl-lib.com ssl/install.com
TEST_ssl=ssl/ssltest.c ssl/heartbeat_test.c
APPS_ssl=

LIB_ssl=libssl.a
SHARED_LIB_ssl= libssl$(SHLIB_EXT)
LIBSRC_ssl=	\
	ssl/s2_meth.c   ssl/s2_srvr.c ssl/s2_clnt.c  ssl/s2_lib.c  ssl/s2_enc.c ssl/s2_pkt.c \
	ssl/s3_meth.c   ssl/s3_srvr.c ssl/s3_clnt.c  ssl/s3_lib.c  ssl/s3_enc.c ssl/s3_pkt.c ssl/s3_both.c ssl/s3_cbc.c \
	ssl/s23_meth.c ssl/s23_srvr.c ssl/s23_clnt.c ssl/s23_lib.c          ssl/s23_pkt.c \
	ssl/t1_meth.c   ssl/t1_srvr.c ssl/t1_clnt.c  ssl/t1_lib.c  ssl/t1_enc.c ssl/t1_ext.c \
	ssl/d1_meth.c   ssl/d1_srvr.c ssl/d1_clnt.c  ssl/d1_lib.c  ssl/d1_pkt.c \
	ssl/d1_both.c ssl/d1_enc.c ssl/d1_srtp.c \
	ssl/ssl_lib.c ssl/ssl_err2.c ssl/ssl_cert.c ssl/ssl_sess.c \
	ssl/ssl_ciph.c ssl/ssl_stat.c ssl/ssl_rsa.c \
	ssl/ssl_asn1.c ssl/ssl_txt.c ssl/ssl_algs.c ssl/ssl_conf.c \
	ssl/bio_ssl.c ssl/ssl_err.c ssl/kssl.c ssl/t1_reneg.c ssl/tls_srp.c ssl/t1_trce.c ssl/ssl_utst.c
LIBOBJ_ssl= \
	ssl/s2_meth.o  ssl/s2_srvr.o  ssl/s2_clnt.o  ssl/s2_lib.o  ssl/s2_enc.o ssl/s2_pkt.o \
	ssl/s3_meth.o  ssl/s3_srvr.o  ssl/s3_clnt.o  ssl/s3_lib.o  ssl/s3_enc.o ssl/s3_pkt.o ssl/s3_both.o ssl/s3_cbc.o \
	ssl/s23_meth.o ssl/s23_srvr.o ssl/s23_clnt.o ssl/s23_lib.o          ssl/s23_pkt.o \
	ssl/t1_meth.o   ssl/t1_srvr.o ssl/t1_clnt.o  ssl/t1_lib.o  ssl/t1_enc.o ssl/t1_ext.o \
	ssl/d1_meth.o   ssl/d1_srvr.o ssl/d1_clnt.o  ssl/d1_lib.o  ssl/d1_pkt.o \
	ssl/d1_both.o ssl/d1_enc.o ssl/d1_srtp.o\
	ssl/ssl_lib.o ssl/ssl_err2.o ssl/ssl_cert.o ssl/ssl_sess.o \
	ssl/ssl_ciph.o ssl/ssl_stat.o ssl/ssl_rsa.o \
	ssl/ssl_asn1.o ssl/ssl_txt.o ssl/ssl_algs.o ssl/ssl_conf.o \
	ssl/bio_ssl.o ssl/ssl_err.o ssl/kssl.o ssl/t1_reneg.o ssl/tls_srp.o ssl/t1_trce.o ssl/ssl_utst.o

SRC_ssl= $(LIBSRC_ssl)

EXHEADER_ssl= ssl/ssl.h ssl/ssl2.h ssl/ssl3.h ssl/ssl23.h ssl/tls1.h ssl/dtls1.h ssl/kssl.h ssl/srtp.h
HEADER_ssl=	$(EXHEADER_ssl) ssl/ssl_locl.h ssl/kssl_lcl.h

ALL_ssl=    $(GENERAL_ssl) $(SRC_ssl) $(HEADER_ssl)


all: all_ssl
all_ssl:	shared_ssl

ssl/lib:	$(LIBOBJ_ssl)
	$(AR) $(LIB_ssl) $(LIBOBJ_ssl)
	$(RANLIB) $(LIB_ssl) || echo Never mind.
	@touch ssl/lib

shared: shared_ssl

files: files_ssl
files_ssl:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_ssl
links_ssl:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_ssl)
	@$(PERL) util/mklink.pl ./test $(TEST_ssl)
	@$(PERL) util/mklink.pl ./apps $(APPS_ssl)

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
	lint -DLINT $(INCLUDES_ssl) $(SRC_ssl)>ssl/fluff

dclean: dclean_ssl
dclean_ssl:

clean: clean_ssl
clean_ssl:
	rm -f ssl/*.o ssl/*.d ssl/*.obj ssl/lib ssl/tags ssl/core ssl/.pure ssl/.nfs* ssl/*.old ssl/*.bak ssl/fluff

