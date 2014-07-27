#
# OpenSSL/crypto/buffer/Makefile
#

DIR_crypto_buffer=	buffer
INCLUDES_crypto_buffer= -I.. -I$(TOP_crypto_buffer) -I../../include

CFLAGS_crypto_buffer= $(INCLUDES_crypto_buffer) $(CFLAG)

GENERAL_crypto_buffer=Makefile
TEST_crypto_buffer=
APPS_crypto_buffer=

LIB_crypto_buffer=$(TOP_crypto_buffer)/libcrypto.a
LIBSRC_crypto_buffer= buffer.c buf_str.c buf_err.c
LIBOBJ_crypto_buffer= buffer.o buf_str.o buf_err.o

SRC_crypto_buffer= $(LIBSRC_crypto_buffer)

EXHEADER_crypto_buffer= buffer.h
HEADER_crypto_buffer=	$(EXHEADER_crypto_buffer)

ALL_crypto_buffer=    $(GENERAL_crypto_buffer) $(SRC_crypto_buffer) $(HEADER_crypto_buffer)

top: top_crypto_buffer
top_crypto_buffer:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_buffer) sub_all)

all: all_crypto_buffer
all_crypto_buffer:	lib

lib:	$(LIBOBJ_crypto_buffer)
	$(ARX) $(LIB_crypto_buffer) $(LIBOBJ_crypto_buffer)
	$(RANLIB) $(LIB_crypto_buffer) || echo Never mind.
	@touch lib

files: files_crypto_buffer
files_crypto_buffer:
	$(PERL) $(TOP_crypto_buffer)/util/files.pl TOP=$(TOP_crypto_buffer) Makefile >> $(TOP_crypto_buffer)/MINFO

links: links_crypto_buffer
links_crypto_buffer:
	@$(PERL) $(TOP_crypto_buffer)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_buffer)
	@$(PERL) $(TOP_crypto_buffer)/util/mklink.pl ../../test $(TEST_crypto_buffer)
	@$(PERL) $(TOP_crypto_buffer)/util/mklink.pl ../../apps $(APPS_crypto_buffer)

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
	lint -DLINT $(INCLUDES_crypto_buffer) $(SRC_crypto_buffer)>fluff

dclean: dclean_crypto_buffer
dclean_crypto_buffer:

clean: clean_crypto_buffer
clean_crypto_buffer:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_buffer) $(CPPFLAGS) -c -o $@ $<
