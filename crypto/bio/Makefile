#
# OpenSSL/crypto/bio/Makefile
#

INCLUDES_crypto_bio= -I.. -I$(TOP_crypto_bio) -I../../include

CFLAGS_crypto_bio= $(INCLUDES_crypto_bio) $(CFLAG)

GENERAL_crypto_bio=Makefile
TEST_crypto_bio=
APPS_crypto_bio=

LIB_crypto_bio=$(TOP_crypto_bio)/libcrypto.a
LIBSRC_crypto_bio= bio_lib.c bio_cb.c bio_err.c \
	bss_mem.c bss_null.c bss_fd.c \
	bss_file.c bss_sock.c bss_conn.c \
	bf_null.c bf_buff.c b_print.c b_dump.c \
	b_sock.c bss_acpt.c bf_nbio.c bss_log.c bss_bio.c \
	bss_dgram.c
#	bf_lbuf.c
LIBOBJ_crypto_bio= bio_lib.o bio_cb.o bio_err.o \
	bss_mem.o bss_null.o bss_fd.o \
	bss_file.o bss_sock.o bss_conn.o \
	bf_null.o bf_buff.o b_print.o b_dump.o \
	b_sock.o bss_acpt.o bf_nbio.o bss_log.o bss_bio.o \
	bss_dgram.o
#	bf_lbuf.o

SRC_crypto_bio= $(LIBSRC_crypto_bio)

EXHEADER_crypto_bio= bio.h
HEADER_crypto_bio=	bio_lcl.h $(EXHEADER_crypto_bio)

ALL_crypto_bio=    $(GENERAL_crypto_bio) $(SRC_crypto_bio) $(HEADER_crypto_bio)


all: all_crypto_bio
all_crypto_bio:	lib

lib:	$(LIBOBJ_crypto_bio)
	$(ARX) $(LIB_crypto_bio) $(LIBOBJ_crypto_bio)
	$(RANLIB) $(LIB_crypto_bio) || echo Never mind.
	@touch lib

files: files_crypto_bio
files_crypto_bio:
	$(PERL) $(TOP_crypto_bio)/util/files.pl TOP=$(TOP_crypto_bio) Makefile >> $(TOP_crypto_bio)/MINFO

links: links_crypto_bio
links_crypto_bio:
	@$(PERL) $(TOP_crypto_bio)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_bio)
	@$(PERL) $(TOP_crypto_bio)/util/mklink.pl ../../test $(TEST_crypto_bio)
	@$(PERL) $(TOP_crypto_bio)/util/mklink.pl ../../apps $(APPS_crypto_bio)

install: install_crypto_bio
install_crypto_bio:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_bio)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_bio
tags_crypto_bio:
	ctags $(SRC_crypto_bio)

tests: tests_crypto_bio
tests_crypto_bio:

lint: lint_crypto_bio
lint_crypto_bio:
	lint -DLINT $(INCLUDES_crypto_bio) $(SRC_crypto_bio)>fluff

dclean: dclean_crypto_bio
dclean_crypto_bio:

clean: clean_crypto_bio
clean_crypto_bio:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_bio) $(CPPFLAGS) -c -o $@ $<
