#
# SSLeay/crypto/des/Makefile
#

DIR=	des
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=-I$(TOP) -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=	Makefile.ssl
AR=		ar r
RANLIB=		ranlib
DES_ENC=	des_enc.o fcrypt_b.o
# or use
#DES_ENC=	dx86-elf.o yx86-elf.o

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=destest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	cbc_cksm.c cbc_enc.c  cfb64enc.c cfb_enc.c  \
	ecb3_enc.c ecb_enc.c  enc_read.c enc_writ.c \
	fcrypt.c ofb64enc.c ofb_enc.c  pcbc_enc.c \
	qud_cksm.c rand_key.c rpc_enc.c  set_key.c  \
	des_enc.c fcrypt_b.c \
	xcbc_enc.c \
	str2key.c  cfb64ede.c ofb64ede.c ede_cbcm_enc.c des_old.c des_old2.c \
	read2pwd.c

LIBOBJ= set_key.o  ecb_enc.o  cbc_enc.o \
	ecb3_enc.o cfb64enc.o cfb64ede.o cfb_enc.o  ofb64ede.o \
	enc_read.o enc_writ.o ofb64enc.o \
	ofb_enc.o  str2key.o  pcbc_enc.o qud_cksm.o rand_key.o \
	${DES_ENC} \
	fcrypt.o xcbc_enc.o rpc_enc.o  cbc_cksm.o \
	ede_cbcm_enc.o des_old.o des_old2.o read2pwd.o

SRC= $(LIBSRC)

EXHEADER= des.h des_old.h
HEADER=	des_locl.h rpc_des.h spr.h des_ver.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

des: des.o cbc3_enc.o lib
	$(CC) $(CFLAGS) -o des des.o cbc3_enc.o $(LIB)

# elf
asm/dx86-elf.o: asm/dx86unix.cpp
	$(CPP) -DELF	\
		`(echo $(CFLAGS) | egrep -ie '-[fK]PIC') > /dev/null 2>&1 && echo -DPIC; exit 0`\
		-x c asm/dx86unix.cpp | as -o asm/dx86-elf.o

asm/yx86-elf.o: asm/yx86unix.cpp
	$(CPP) -DELF	\
		`(echo $(CFLAGS) | egrep -ie '-[fK]PIC') > /dev/null 2>&1 && echo -DPIC; exit 0`\
		-x c asm/yx86unix.cpp | as -o asm/yx86-elf.o

# solaris
asm/dx86-sol.o: asm/dx86unix.cpp
	$(CC) -E -DSOL	\
		`(echo $(CFLAGS) | egrep -ie '-[fK]PIC') > /dev/null 2>&1 && echo -DPIC; exit 0`\
		asm/dx86unix.cpp | sed 's/^#.*//' > asm/dx86-sol.s
	as -o asm/dx86-sol.o asm/dx86-sol.s
	rm -f asm/dx86-sol.s

asm/yx86-sol.o: asm/yx86unix.cpp
	$(CC) -E -DSOL	\
		`(echo $(CFLAGS) | egrep -ie '-[fK]PIC') > /dev/null 2>&1 && echo -DPIC; exit 0`\
		asm/yx86unix.cpp | sed 's/^#.*//' > asm/yx86-sol.s
	as -o asm/yx86-sol.o asm/yx86-sol.s
	rm -f asm/yx86-sol.s

# a.out
asm/dx86-out.o: asm/dx86unix.cpp
	$(CPP) -DOUT asm/dx86unix.cpp | as -o asm/dx86-out.o

asm/yx86-out.o: asm/yx86unix.cpp
	$(CPP) -DOUT asm/yx86unix.cpp | as -o asm/yx86-out.o

# bsdi
asm/dx86bsdi.o: asm/dx86unix.cpp
	$(CPP) -DBSDI asm/dx86unix.cpp | sed 's/ :/:/' | as -o asm/dx86bsdi.o

asm/yx86bsdi.o: asm/yx86unix.cpp
	$(CPP) -DBSDI asm/yx86unix.cpp | sed 's/ :/:/' | as -o asm/yx86bsdi.o

asm/dx86unix.cpp: asm/des-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) des-586.pl cpp >dx86unix.cpp)

asm/yx86unix.cpp: asm/crypt586.pl ../perlasm/x86asm.pl
	(cd asm; $(PERL) crypt586.pl cpp >yx86unix.cpp)

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: installs

installs:
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
	rm -f asm/dx86unix.cpp asm/yx86unix.cpp *.o asm/*.o *.obj des lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cbc_cksm.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
cbc_cksm.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
cbc_cksm.o: ../../include/openssl/opensslconf.h
cbc_cksm.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
cbc_cksm.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cbc_cksm.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
cbc_cksm.o: cbc_cksm.c des_locl.h
cbc_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
cbc_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
cbc_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cbc_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cbc_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
cbc_enc.o: ../../include/openssl/ui_compat.h cbc_enc.c des_locl.h ncbc_enc.c
cfb64ede.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
cfb64ede.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
cfb64ede.o: ../../include/openssl/opensslconf.h
cfb64ede.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
cfb64ede.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cfb64ede.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
cfb64ede.o: cfb64ede.c des_locl.h
cfb64enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
cfb64enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
cfb64enc.o: ../../include/openssl/opensslconf.h
cfb64enc.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
cfb64enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cfb64enc.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
cfb64enc.o: cfb64enc.c des_locl.h
cfb_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
cfb_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
cfb_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cfb_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cfb_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
cfb_enc.o: ../../include/openssl/ui_compat.h cfb_enc.c des_locl.h
des_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
des_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
des_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
des_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
des_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
des_enc.o: ../../include/openssl/ui_compat.h des_enc.c des_locl.h ncbc_enc.c
des_old.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
des_old.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
des_old.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
des_old.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
des_old.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
des_old.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
des_old.o: ../../include/openssl/ui_compat.h des_old.c
des_old2.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
des_old2.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
des_old2.o: ../../include/openssl/opensslconf.h
des_old2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
des_old2.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
des_old2.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
des_old2.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
des_old2.o: des_old2.c
ecb3_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
ecb3_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
ecb3_enc.o: ../../include/openssl/opensslconf.h
ecb3_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ecb3_enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecb3_enc.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
ecb3_enc.o: des_locl.h ecb3_enc.c
ecb_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
ecb_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
ecb_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ecb_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ecb_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
ecb_enc.o: ../../include/openssl/ui_compat.h des_locl.h des_ver.h ecb_enc.c
ecb_enc.o: spr.h
ede_cbcm_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
ede_cbcm_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
ede_cbcm_enc.o: ../../include/openssl/opensslconf.h
ede_cbcm_enc.o: ../../include/openssl/opensslv.h
ede_cbcm_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ede_cbcm_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
ede_cbcm_enc.o: ../../include/openssl/ui_compat.h des_locl.h ede_cbcm_enc.c
enc_read.o: ../../e_os.h ../../include/openssl/bio.h
enc_read.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
enc_read.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
enc_read.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
enc_read.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
enc_read.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
enc_read.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
enc_read.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
enc_read.o: ../cryptlib.h des_locl.h enc_read.c
enc_writ.o: ../../e_os.h ../../include/openssl/bio.h
enc_writ.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
enc_writ.o: ../../include/openssl/des.h ../../include/openssl/des_old.h
enc_writ.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
enc_writ.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
enc_writ.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
enc_writ.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
enc_writ.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
enc_writ.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
enc_writ.o: ../cryptlib.h des_locl.h enc_writ.c
fcrypt.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fcrypt.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
fcrypt.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
fcrypt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fcrypt.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
fcrypt.o: ../../include/openssl/ui_compat.h des_locl.h fcrypt.c
fcrypt_b.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
fcrypt_b.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
fcrypt_b.o: ../../include/openssl/opensslconf.h
fcrypt_b.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
fcrypt_b.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fcrypt_b.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
fcrypt_b.o: des_locl.h fcrypt_b.c
ofb64ede.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
ofb64ede.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
ofb64ede.o: ../../include/openssl/opensslconf.h
ofb64ede.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ofb64ede.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ofb64ede.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
ofb64ede.o: des_locl.h ofb64ede.c
ofb64enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
ofb64enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
ofb64enc.o: ../../include/openssl/opensslconf.h
ofb64enc.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
ofb64enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ofb64enc.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
ofb64enc.o: des_locl.h ofb64enc.c
ofb_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
ofb_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
ofb_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ofb_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ofb_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
ofb_enc.o: ../../include/openssl/ui_compat.h des_locl.h ofb_enc.c
pcbc_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
pcbc_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
pcbc_enc.o: ../../include/openssl/opensslconf.h
pcbc_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
pcbc_enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pcbc_enc.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
pcbc_enc.o: des_locl.h pcbc_enc.c
qud_cksm.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
qud_cksm.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
qud_cksm.o: ../../include/openssl/opensslconf.h
qud_cksm.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
qud_cksm.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
qud_cksm.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
qud_cksm.o: des_locl.h qud_cksm.c
rand_key.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
rand_key.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
rand_key.o: ../../include/openssl/opensslconf.h
rand_key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_key.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_key.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_key.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
rand_key.o: rand_key.c
read2pwd.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
read2pwd.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
read2pwd.o: ../../include/openssl/opensslconf.h
read2pwd.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
read2pwd.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
read2pwd.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
read2pwd.o: read2pwd.c
rpc_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
rpc_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
rpc_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rpc_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
rpc_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
rpc_enc.o: ../../include/openssl/ui_compat.h des_locl.h des_ver.h rpc_des.h
rpc_enc.o: rpc_enc.c
set_key.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
set_key.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
set_key.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
set_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
set_key.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
set_key.o: ../../include/openssl/ui_compat.h des_locl.h set_key.c
str2key.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
str2key.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
str2key.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
str2key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
str2key.o: ../../include/openssl/symhacks.h ../../include/openssl/ui.h
str2key.o: ../../include/openssl/ui_compat.h des_locl.h str2key.c
xcbc_enc.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
xcbc_enc.o: ../../include/openssl/des_old.h ../../include/openssl/e_os2.h
xcbc_enc.o: ../../include/openssl/opensslconf.h
xcbc_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
xcbc_enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
xcbc_enc.o: ../../include/openssl/ui.h ../../include/openssl/ui_compat.h
xcbc_enc.o: des_locl.h xcbc_enc.c
