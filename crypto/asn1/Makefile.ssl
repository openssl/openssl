#
# SSLeay/crypto/asn1/Makefile
#

DIR=	asn1
TOP=	../..
CC=	cc
INCLUDES= -I.. -I../../include
CFLAG=-g
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	makedepend -f Makefile.ssl
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

ERR=asn1
ERRC=asn1_err
GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	a_object.c a_bitstr.c a_utctm.c a_int.c a_octet.c a_print.c \
	a_type.c a_set.c a_dup.c a_d2i_fp.c a_i2d_fp.c \
	a_sign.c a_digest.c a_verify.c \
	x_algor.c x_val.c x_pubkey.c x_sig.c x_req.c x_attrib.c \
	x_name.c x_cinf.c x_x509.c x_crl.c x_info.c x_spki.c \
	d2i_r_pr.c i2d_r_pr.c d2i_r_pu.c i2d_r_pu.c \
	d2i_s_pr.c i2d_s_pr.c d2i_s_pu.c i2d_s_pu.c \
	d2i_pu.c d2i_pr.c i2d_pu.c i2d_pr.c\
	t_req.c t_x509.c t_pkey.c \
	p7_i_s.c p7_signi.c p7_signd.c p7_recip.c p7_enc_c.c p7_evp.c \
	p7_dgst.c p7_s_e.c p7_enc.c p7_lib.c \
	f_int.c f_string.c i2d_dhp.c i2d_dsap.c d2i_dhp.c d2i_dsap.c n_pkey.c \
	a_hdr.c x_pkey.c a_bool.c x_exten.c \
	asn1_par.c asn1_lib.c $(ERRC).c a_meth.c a_bytes.c \
	evp_asn1.c
LIBOBJ= a_object.o a_bitstr.o a_utctm.o a_int.o a_octet.o a_print.o \
	a_type.o a_set.o a_dup.o a_d2i_fp.o a_i2d_fp.o \
	a_sign.o a_digest.o a_verify.o \
	x_algor.o x_val.o x_pubkey.o x_sig.o x_req.o x_attrib.o \
	x_name.o x_cinf.o x_x509.o x_crl.o x_info.o x_spki.o \
	d2i_r_pr.o i2d_r_pr.o d2i_r_pu.o i2d_r_pu.o \
	d2i_s_pr.o i2d_s_pr.o d2i_s_pu.o i2d_s_pu.o \
	d2i_pu.o d2i_pr.o i2d_pu.o i2d_pr.o \
	t_req.o t_x509.o t_pkey.o \
	p7_i_s.o p7_signi.o p7_signd.o p7_recip.o p7_enc_c.o p7_evp.o \
	p7_dgst.o p7_s_e.o p7_enc.o p7_lib.o \
	f_int.o f_string.o i2d_dhp.o i2d_dsap.o d2i_dhp.o d2i_dsap.o n_pkey.o \
	a_hdr.o x_pkey.o a_bool.o x_exten.o \
	asn1_par.o asn1_lib.o $(ERRC).o a_meth.o a_bytes.o \
	evp_asn1.o

SRC= $(LIBSRC)

EXHEADER=  asn1.h asn1_mac.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:	test.c
	cc -g -I../../include -c test.c
	cc -g -I../../include -o test test.o -L../.. -lcrypto

pk:	pk.c
	cc -g -I../../include -c pk.c
	cc -g -I../../include -o pk pk.o -L../.. -lcrypto

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
	$(TOP)/util/mklink.sh ../../include $(EXHEADER)
	$(TOP)/util/mklink.sh ../../test $(TEST)
	$(TOP)/util/mklink.sh ../../apps $(APPS)

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
	perl ../err/err_genc.pl -s $(ERR).h $(ERRC).c

# DO NOT DELETE THIS LINE -- make depend depends on it.
