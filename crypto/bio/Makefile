#
# OpenSSL/crypto/bio/Makefile
#

DIR=	bio
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
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
	b_sock.c bss_acpt.c bf_nbio.c bss_log.c bss_bio.c \
	bss_dgram.c
#	bf_lbuf.c
LIBOBJ= bio_lib.o bio_cb.o bio_err.o \
	bss_mem.o bss_null.o bss_fd.o \
	bss_file.o bss_sock.o bss_conn.o \
	bf_null.o bf_buff.o b_print.o b_dump.o \
	b_sock.o bss_acpt.o bf_nbio.o bss_log.o bss_bio.o \
	bss_dgram.o
#	bf_lbuf.o

SRC= $(LIBSRC)

EXHEADER= bio.h
HEADER=	bio_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
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
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

b_dump.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
b_dump.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
b_dump.o: ../../include/openssl/stack.h ../cryptlib.h b_dump.c bio_lcl.h
b_print.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
b_print.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
b_print.o: ../../include/openssl/stack.h ../cryptlib.h b_print.c
b_sock.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/dso.h
b_sock.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
b_sock.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
b_sock.o: ../cryptlib.h b_sock.c
bf_buff.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bf_buff.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bf_buff.o: ../../include/openssl/stack.h ../cryptlib.h bf_buff.c
bf_nbio.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bf_nbio.o: ../../include/openssl/lhash.h ../../include/openssl/rand.h
bf_nbio.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bf_nbio.o: ../cryptlib.h bf_nbio.c
bf_null.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bf_null.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bf_null.o: ../../include/openssl/stack.h ../cryptlib.h bf_null.c
bio_cb.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bio_cb.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bio_cb.o: ../../include/openssl/stack.h ../cryptlib.h bio_cb.c
bio_err.o: ../../include/openssl/bio.h ../../include/openssl/err.h
bio_err.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bio_err.o: ../../include/openssl/stack.h bio_err.c
bio_lib.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bio_lib.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bio_lib.o: ../../include/openssl/stack.h ../cryptlib.h bio_lib.c
bss_acpt.o: ../../e_os.h ../../include/openssl/bio.h
bss_acpt.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_acpt.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_acpt.o: ../cryptlib.h bss_acpt.c
bss_bio.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bss_bio.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bss_bio.o: ../../include/openssl/stack.h bss_bio.c
bss_conn.o: ../../e_os.h ../../include/openssl/bio.h
bss_conn.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_conn.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_conn.o: ../cryptlib.h bss_conn.c
bss_dgram.o: ../../e_os.h ../../include/openssl/bio.h
bss_dgram.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_dgram.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_dgram.o: ../cryptlib.h bss_dgram.c
bss_fd.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bss_fd.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bss_fd.o: ../../include/openssl/stack.h ../cryptlib.h bio_lcl.h bss_fd.c
bss_file.o: ../../e_os.h ../../include/openssl/bio.h
bss_file.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_file.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_file.o: ../cryptlib.h bio_lcl.h bss_file.c
bss_log.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bss_log.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bss_log.o: ../../include/openssl/stack.h ../cryptlib.h bss_log.c
bss_mem.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/err.h
bss_mem.o: ../../include/openssl/lhash.h ../../include/openssl/safestack.h
bss_mem.o: ../../include/openssl/stack.h ../cryptlib.h bss_mem.c
bss_null.o: ../../e_os.h ../../include/openssl/bio.h
bss_null.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_null.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_null.o: ../cryptlib.h bss_null.c
bss_sock.o: ../../e_os.h ../../include/openssl/bio.h
bss_sock.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
bss_sock.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
bss_sock.o: ../cryptlib.h bss_sock.c
