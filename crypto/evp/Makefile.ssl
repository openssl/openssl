#
# SSLeay/crypto/evp/Makefile
#

DIR=	evp
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

ERR=evp
ERRC=evp_err
GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= encode.c digest.c evp_enc.c evp_key.c \
	e_ecb_d.c e_cbc_d.c e_cfb_d.c e_ofb_d.c \
	e_ecb_i.c e_cbc_i.c e_cfb_i.c e_ofb_i.c \
	e_ecb_3d.c e_cbc_3d.c e_rc4.c names.c \
	e_cfb_3d.c e_ofb_3d.c e_xcbc_d.c \
	e_ecb_r2.c e_cbc_r2.c e_cfb_r2.c e_ofb_r2.c \
	e_ecb_bf.c e_cbc_bf.c e_cfb_bf.c e_ofb_bf.c \
	e_ecb_c.c e_cbc_c.c e_cfb_c.c e_ofb_c.c \
	e_ecb_r5.c e_cbc_r5.c e_cfb_r5.c e_ofb_r5.c \
	m_null.c m_md2.c m_md5.c m_sha.c m_sha1.c m_dss.c m_dss1.c m_mdc2.c \
	m_ripemd.c \
	p_open.c p_seal.c p_sign.c p_verify.c p_lib.c p_enc.c p_dec.c \
	bio_md.c bio_b64.c bio_enc.c $(ERRC).c e_null.c \
	c_all.c evp_lib.c

LIBOBJ=	encode.o digest.o evp_enc.o evp_key.o \
	e_ecb_d.o e_cbc_d.o e_cfb_d.o e_ofb_d.o \
	e_ecb_i.o e_cbc_i.o e_cfb_i.o e_ofb_i.o \
	e_ecb_3d.o e_cbc_3d.o e_rc4.o names.o \
	e_cfb_3d.o e_ofb_3d.o e_xcbc_d.o \
	e_ecb_r2.o e_cbc_r2.o e_cfb_r2.o e_ofb_r2.o \
	e_ecb_bf.o e_cbc_bf.o e_cfb_bf.o e_ofb_bf.o \
	e_ecb_c.o e_cbc_c.o e_cfb_c.o e_ofb_c.o \
	e_ecb_r5.o e_cbc_r5.o e_cfb_r5.o e_ofb_r5.o \
	m_null.o m_md2.o m_md5.o m_sha.o m_sha1.o m_dss.o m_dss1.o m_mdc2.o \
	m_ripemd.o \
	p_open.o p_seal.o p_sign.o p_verify.o p_lib.o p_enc.o p_dec.o \
	bio_md.o bio_b64.o bio_enc.o $(ERRC).o e_null.o \
	c_all.o evp_lib.o

SRC= $(LIBSRC)

EXHEADER= evp.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

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
	$(MAKEDEPEND) $(INCLUDES) $(LIBSRC)

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	/bin/rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

errors:
	perl $(TOP)/util/err-ins.pl $(ERR).err $(ERR).h
	perl ../err/err_genc.pl -s $(ERR).h $(ERRC).c

# DO NOT DELETE THIS LINE -- make depend depends on it.
