#
# OpenSSL/crypto/des/Makefile
#

DIR=	des
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=-I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r
RANLIB=		ranlib
DES_ENC=	des_enc.o fcrypt_b.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=	cbc_cksm.c cbc_enc.c  cfb64enc.c cfb_enc.c  \
	ecb3_enc.c ecb_enc.c  enc_read.c enc_writ.c \
	fcrypt.c ofb64enc.c ofb_enc.c  pcbc_enc.c \
	qud_cksm.c rand_key.c rpc_enc.c  set_key.c  \
	des_enc.c fcrypt_b.c \
	xcbc_enc.c \
	str2key.c  cfb64ede.c ofb64ede.c \
	read2pwd.c

LIBOBJ= set_key.o  ecb_enc.o  cbc_enc.o \
	ecb3_enc.o cfb64enc.o cfb64ede.o cfb_enc.o  ofb64ede.o \
	enc_read.o enc_writ.o ofb64enc.o \
	ofb_enc.o  str2key.o  pcbc_enc.o qud_cksm.o rand_key.o \
	${DES_ENC} \
	fcrypt.o xcbc_enc.o rpc_enc.o  cbc_cksm.o \
	read2pwd.o

SRC= $(LIBSRC)

HEADER=	des_locl.h rpc_des.h spr.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

des_enc-sparc.S:	asm/des_enc.m4
	m4 -B 8192 asm/des_enc.m4 > des_enc-sparc.S
dest4-sparcv9.s:	asm/dest4-sparcv9.pl
	$(PERL) asm/dest4-sparcv9.pl $(CFLAGS) > $@

des-586.s:	asm/des-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/des-586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@
crypt586.s:	asm/crypt586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	$(PERL) asm/crypt586.pl $(PERLASM_SCHEME) $(CFLAGS) > $@

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
	rm -f *.s *.o *.obj des lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cbc_cksm.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
cbc_cksm.o: ../../include/openssl/opensslconf.h cbc_cksm.c des_locl.h
cbc_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
cbc_enc.o: ../../include/openssl/opensslconf.h cbc_enc.c des_locl.h ncbc_enc.c
cfb64ede.o: ../../e_os.h ../../include/openssl/des.h
cfb64ede.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
cfb64ede.o: cfb64ede.c des_locl.h
cfb64enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
cfb64enc.o: ../../include/openssl/opensslconf.h cfb64enc.c des_locl.h
cfb_enc.o: ../../e_os.h ../../include/openssl/des.h
cfb_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
cfb_enc.o: cfb_enc.c des_locl.h
des_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
des_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
des_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
des_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
des_enc.o: ../../include/openssl/symhacks.h des_enc.c des_locl.h ncbc_enc.c
des_enc.o: spr.h
ecb3_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
ecb3_enc.o: ../../include/openssl/opensslconf.h des_locl.h ecb3_enc.c
ecb_enc.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
ecb_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
ecb_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ecb_enc.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
ecb_enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecb_enc.o: des_locl.h ecb_enc.c
enc_read.o: ../../e_os.h ../../include/openssl/bio.h
enc_read.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
enc_read.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
enc_read.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
enc_read.o: ../../include/openssl/opensslconf.h
enc_read.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
enc_read.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
enc_read.o: ../../include/openssl/symhacks.h ../include/internal/cryptlib.h
enc_read.o: des_locl.h enc_read.c
enc_writ.o: ../../e_os.h ../../include/openssl/bio.h
enc_writ.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
enc_writ.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
enc_writ.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
enc_writ.o: ../../include/openssl/opensslconf.h
enc_writ.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
enc_writ.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
enc_writ.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
enc_writ.o: ../include/internal/cryptlib.h des_locl.h enc_writ.c
fcrypt.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fcrypt.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
fcrypt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fcrypt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fcrypt.o: ../../include/openssl/symhacks.h des_locl.h fcrypt.c
fcrypt_b.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
fcrypt_b.o: ../../include/openssl/opensslconf.h des_locl.h fcrypt_b.c
ofb64ede.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
ofb64ede.o: ../../include/openssl/opensslconf.h des_locl.h ofb64ede.c
ofb64enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
ofb64enc.o: ../../include/openssl/opensslconf.h des_locl.h ofb64enc.c
ofb_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
ofb_enc.o: ../../include/openssl/opensslconf.h des_locl.h ofb_enc.c
pcbc_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
pcbc_enc.o: ../../include/openssl/opensslconf.h des_locl.h pcbc_enc.c
qud_cksm.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
qud_cksm.o: ../../include/openssl/opensslconf.h des_locl.h qud_cksm.c
rand_key.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
rand_key.o: ../../include/openssl/opensslconf.h
rand_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
rand_key.o: rand_key.c
read2pwd.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
read2pwd.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
read2pwd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
read2pwd.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
read2pwd.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
read2pwd.o: read2pwd.c
rpc_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
rpc_enc.o: ../../include/openssl/opensslconf.h des_locl.h rpc_des.h rpc_enc.c
set_key.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
set_key.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
set_key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
set_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
set_key.o: ../../include/openssl/symhacks.h des_locl.h set_key.c
str2key.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
str2key.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
str2key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
str2key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
str2key.o: ../../include/openssl/symhacks.h des_locl.h str2key.c
xcbc_enc.o: ../../include/openssl/des.h ../../include/openssl/e_os2.h
xcbc_enc.o: ../../include/openssl/opensslconf.h des_locl.h xcbc_enc.c
