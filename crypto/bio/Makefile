#
# OpenSSL/crypto/bio/Makefile
#

INCLUDES_crypto_bio= -Icrypto -I. -Iinclude

CFLAGS_crypto_bio= $(INCLUDES_crypto_bio) $(CFLAG)

GENERAL_crypto_bio=crypto/bio/Makefile
TEST_crypto_bio=
APPS_crypto_bio=

LIB_crypto_bio=libcrypto.a
LIBSRC_crypto_bio= crypto/bio/bio_lib.c crypto/bio/bio_cb.c crypto/bio/bio_err.c \
	crypto/bio/bss_mem.c crypto/bio/bss_null.c crypto/bio/bss_fd.c \
	crypto/bio/bss_file.c crypto/bio/bss_sock.c crypto/bio/bss_conn.c \
	crypto/bio/bf_null.c crypto/bio/bf_buff.c crypto/bio/b_print.c crypto/bio/b_dump.c \
	crypto/bio/b_sock.c crypto/bio/bss_acpt.c crypto/bio/bf_nbio.c crypto/bio/bss_log.c crypto/bio/bss_bio.c \
	crypto/bio/bss_dgram.c
#	bf_lbuf.c
LIBOBJ_crypto_bio= crypto/bio/bio_lib.o crypto/bio/bio_cb.o crypto/bio/bio_err.o \
	crypto/bio/bss_mem.o crypto/bio/bss_null.o crypto/bio/bss_fd.o \
	crypto/bio/bss_file.o crypto/bio/bss_sock.o crypto/bio/bss_conn.o \
	crypto/bio/bf_null.o crypto/bio/bf_buff.o crypto/bio/b_print.o crypto/bio/b_dump.o \
	crypto/bio/b_sock.o crypto/bio/bss_acpt.o crypto/bio/bf_nbio.o crypto/bio/bss_log.o crypto/bio/bss_bio.o \
	crypto/bio/bss_dgram.o
#	bf_lbuf.o

SRC_crypto_bio= $(LIBSRC_crypto_bio)

EXHEADER_crypto_bio= crypto/bio/bio.h
HEADER_crypto_bio=	crypto/bio/bio_lcl.h $(EXHEADER_crypto_bio)

ALL_crypto_bio=    $(GENERAL_crypto_bio) $(SRC_crypto_bio) $(HEADER_crypto_bio)


all: all_crypto_bio
all_crypto_bio:	crypto/bio/lib

crypto/bio/lib:	$(LIBOBJ_crypto_bio)
	$(ARX) $(LIB_crypto_bio) $(LIBOBJ_crypto_bio)
	$(RANLIB) $(LIB_crypto_bio) || echo Never mind.
	@touch crypto/bio/lib

files: files_crypto_bio
files_crypto_bio:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_bio
links_crypto_bio:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_bio)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_bio)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_bio)

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
	lint -DLINT $(INCLUDES_crypto_bio) $(SRC_crypto_bio)>crypto/bio/fluff

dclean: dclean_crypto_bio
dclean_crypto_bio:

clean: clean_crypto_bio
clean_crypto_bio:
	rm -f crypto/bio/*.o crypto/bio/*.d crypto/bio/*.obj crypto/bio/lib crypto/bio/tags crypto/bio/core crypto/bio/.pure crypto/bio/.nfs* crypto/bio/*.old crypto/bio/*.bak crypto/bio/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_bio) $(CPPFLAGS) -c -o $@ $<
