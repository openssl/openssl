#
# OpenSSL/crypto/buffer/Makefile
#

INCLUDES_crypto_buffer= -Icrypto -I. -Iinclude

CFLAGS_crypto_buffer= $(INCLUDES_crypto_buffer) $(CFLAG)

GENERAL_crypto_buffer=crypto/buffer/Makefile
TEST_crypto_buffer=
APPS_crypto_buffer=

LIB_crypto_buffer=libcrypto.a
LIBSRC_crypto_buffer= crypto/buffer/buffer.c crypto/buffer/buf_str.c crypto/buffer/buf_err.c
LIBOBJ_crypto_buffer= crypto/buffer/buffer.o crypto/buffer/buf_str.o crypto/buffer/buf_err.o

SRC_crypto_buffer= $(LIBSRC_crypto_buffer)

EXHEADER_crypto_buffer= crypto/buffer/buffer.h
HEADER_crypto_buffer=	$(EXHEADER_crypto_buffer)

ALL_crypto_buffer=    $(GENERAL_crypto_buffer) $(SRC_crypto_buffer) $(HEADER_crypto_buffer)


all: all_crypto_buffer
all_crypto_buffer:	crypto/buffer/lib

crypto/buffer/lib:	$(LIBOBJ_crypto_buffer)
	$(ARX) $(LIB_crypto_buffer) $(LIBOBJ_crypto_buffer)
	$(RANLIB) $(LIB_crypto_buffer) || echo Never mind.
	@touch crypto/buffer/lib

files: files_crypto_buffer
files_crypto_buffer:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_buffer
links_crypto_buffer:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_buffer)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_buffer)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_buffer)

install: install_crypto_buffer
install_crypto_buffer:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_buffer)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_buffer
tags_crypto_buffer:
	ctags $(SRC_crypto_buffer)

tests: tests_crypto_buffer
tests_crypto_buffer:

lint: lint_crypto_buffer
lint_crypto_buffer:
	lint -DLINT $(INCLUDES_crypto_buffer) $(SRC_crypto_buffer)>crypto/buffer/fluff

dclean: dclean_crypto_buffer
dclean_crypto_buffer:

clean: clean_crypto_buffer
clean_crypto_buffer:
	rm -f crypto/buffer/*.o crypto/buffer/*.d crypto/buffer/*.obj crypto/buffer/lib crypto/buffer/tags crypto/buffer/core crypto/buffer/.pure crypto/buffer/.nfs* crypto/buffer/*.old crypto/buffer/*.bak crypto/buffer/fluff

