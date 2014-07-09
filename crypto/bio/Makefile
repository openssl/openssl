#
# OpenSSL/crypto/bio/Makefile
#

DIR=	bio
INCLUDES= -I.. -I$(TOP) -I../../include

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
	$(ARX) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

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

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

