#
# SSLeay/crypto/bio/Makefile
#

DIR=	bio
TOP=	../..
CC=	cc
INCLUDES= -I.. -I../../include
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= bio_lib.c bio_cb.c bio_err.c \
	bss_mem.c bss_null.c bss_fd.c \
	bss_file.c bss_sock.c bss_conn.c \
	bf_null.c bf_buff.c b_print.c b_dump.c \
	b_sock.c bss_acpt.c bf_nbio.c bss_log.c bss_bio.c
#	bf_lbuf.c
LIBOBJ= bio_lib.o bio_cb.o bio_err.o \
	bss_mem.o bss_null.o bss_fd.o \
	bss_file.o bss_sock.o bss_conn.o \
	bf_null.o bf_buff.o b_print.o b_dump.o \
	b_sock.o bss_acpt.o bf_nbio.o bss_log.o bss_bio.o
#	bf_lbuf.o

SRC= $(LIBSRC)

EXHEADER= bio.h
HEADER=	bss_file.c $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	@echo You may get an error following this line.  Please ignore.
	- $(RANLIB) $(LIB)
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@for i in $(EXHEADER); \
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
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

b_dump.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
b_dump.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
b_dump.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
b_dump.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
b_dump.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
b_dump.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
b_dump.o: ../cryptlib.h
b_print.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
b_print.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
b_print.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
b_print.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
b_print.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
b_print.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
b_print.o: ../../include/openssl/symhacks.h ../cryptlib.h
b_sock.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
b_sock.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
b_sock.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
b_sock.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
b_sock.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
b_sock.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
b_sock.o: ../cryptlib.h
bf_buff.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bf_buff.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
bf_buff.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
bf_buff.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
bf_buff.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
bf_buff.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bf_buff.o: ../../include/openssl/err.h ../../include/openssl/evp.h
bf_buff.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
bf_buff.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
bf_buff.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
bf_buff.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
bf_buff.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bf_buff.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
bf_buff.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
bf_buff.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
bf_buff.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
bf_buff.o: ../../include/openssl/symhacks.h ../cryptlib.h
bf_nbio.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bf_nbio.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
bf_nbio.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
bf_nbio.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
bf_nbio.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
bf_nbio.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bf_nbio.o: ../../include/openssl/err.h ../../include/openssl/evp.h
bf_nbio.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
bf_nbio.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
bf_nbio.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
bf_nbio.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
bf_nbio.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bf_nbio.o: ../../include/openssl/rand.h ../../include/openssl/rc2.h
bf_nbio.o: ../../include/openssl/rc4.h ../../include/openssl/rc5.h
bf_nbio.o: ../../include/openssl/ripemd.h ../../include/openssl/rsa.h
bf_nbio.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
bf_nbio.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bf_nbio.o: ../cryptlib.h
bf_null.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
bf_null.o: ../../include/openssl/blowfish.h ../../include/openssl/bn.h
bf_null.o: ../../include/openssl/buffer.h ../../include/openssl/cast.h
bf_null.o: ../../include/openssl/crypto.h ../../include/openssl/des.h
bf_null.o: ../../include/openssl/dh.h ../../include/openssl/dsa.h
bf_null.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bf_null.o: ../../include/openssl/err.h ../../include/openssl/evp.h
bf_null.o: ../../include/openssl/idea.h ../../include/openssl/lhash.h
bf_null.o: ../../include/openssl/md2.h ../../include/openssl/md4.h
bf_null.o: ../../include/openssl/md5.h ../../include/openssl/mdc2.h
bf_null.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
bf_null.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bf_null.o: ../../include/openssl/rc2.h ../../include/openssl/rc4.h
bf_null.o: ../../include/openssl/rc5.h ../../include/openssl/ripemd.h
bf_null.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
bf_null.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
bf_null.o: ../../include/openssl/symhacks.h ../cryptlib.h
bio_cb.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bio_cb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bio_cb.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bio_cb.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bio_cb.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bio_cb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bio_cb.o: ../cryptlib.h
bio_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
bio_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bio_err.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bio_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bio_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bio_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bio_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bio_lib.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bio_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bio_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bio_lib.o: ../cryptlib.h
bss_acpt.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_acpt.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_acpt.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_acpt.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_acpt.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_acpt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_acpt.o: ../cryptlib.h
bss_bio.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
bss_bio.o: ../../include/openssl/e_os.h ../../include/openssl/e_os2.h
bss_bio.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_bio.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
bss_bio.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_bio.o: ../../include/openssl/symhacks.h
bss_conn.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_conn.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_conn.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_conn.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_conn.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_conn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_conn.o: ../cryptlib.h
bss_fd.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_fd.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_fd.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_fd.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_fd.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_fd.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_fd.o: ../cryptlib.h bss_sock.c
bss_file.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_file.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_file.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_file.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_file.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_file.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_file.o: ../cryptlib.h
bss_log.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_log.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_log.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_log.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_log.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_log.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_log.o: ../cryptlib.h
bss_mem.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_mem.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_mem.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_mem.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_mem.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_mem.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_mem.o: ../cryptlib.h
bss_null.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_null.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_null.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_null.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_null.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_null.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_null.o: ../cryptlib.h
bss_sock.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
bss_sock.o: ../../include/openssl/crypto.h ../../include/openssl/e_os.h
bss_sock.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
bss_sock.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
bss_sock.o: ../../include/openssl/opensslv.h ../../include/openssl/safestack.h
bss_sock.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
bss_sock.o: ../cryptlib.h
