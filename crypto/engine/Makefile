#
# OpenSSL/crypto/engine/Makefile
#

INCLUDES_crypto_engine= -Icrypto -I. -Iinclude

CFLAGS_crypto_engine= $(INCLUDES_crypto_engine) $(CFLAG)

GENERAL_crypto_engine=crypto/engine/Makefile
TEST_crypto_engine= crypto/engine/enginetest.c
APPS_crypto_engine=

LIB_crypto_engine=libcrypto.a
LIBSRC_crypto_engine= crypto/engine/eng_err.c crypto/engine/eng_lib.c crypto/engine/eng_list.c crypto/engine/eng_init.c crypto/engine/eng_ctrl.c \
	crypto/engine/eng_table.c crypto/engine/eng_pkey.c crypto/engine/eng_fat.c crypto/engine/eng_all.c \
	crypto/engine/tb_rsa.c crypto/engine/tb_dsa.c crypto/engine/tb_ecdsa.c crypto/engine/tb_dh.c crypto/engine/tb_ecdh.c crypto/engine/tb_rand.c crypto/engine/tb_store.c \
	crypto/engine/tb_cipher.c crypto/engine/tb_digest.c crypto/engine/tb_pkmeth.c crypto/engine/tb_asnmth.c \
	crypto/engine/eng_openssl.c crypto/engine/eng_cnf.c crypto/engine/eng_dyn.c crypto/engine/eng_cryptodev.c \
	crypto/engine/eng_rdrand.c
LIBOBJ_crypto_engine= crypto/engine/eng_err.o crypto/engine/eng_lib.o crypto/engine/eng_list.o crypto/engine/eng_init.o crypto/engine/eng_ctrl.o \
	crypto/engine/eng_table.o crypto/engine/eng_pkey.o crypto/engine/eng_fat.o crypto/engine/eng_all.o \
	crypto/engine/tb_rsa.o crypto/engine/tb_dsa.o crypto/engine/tb_ecdsa.o crypto/engine/tb_dh.o crypto/engine/tb_ecdh.o crypto/engine/tb_rand.o crypto/engine/tb_store.o \
	crypto/engine/tb_cipher.o crypto/engine/tb_digest.o crypto/engine/tb_pkmeth.o crypto/engine/tb_asnmth.o \
	crypto/engine/eng_openssl.o crypto/engine/eng_cnf.o crypto/engine/eng_dyn.o crypto/engine/eng_cryptodev.o \
	crypto/engine/eng_rdrand.o

SRC_crypto_engine= $(LIBSRC_crypto_engine)

EXHEADER_crypto_engine= crypto/engine/engine.h
HEADER_crypto_engine=	$(EXHEADER_crypto_engine)

ALL_crypto_engine=    $(GENERAL_crypto_engine) $(SRC_crypto_engine) $(HEADER_crypto_engine)


all: all_crypto_engine
all_crypto_engine:	crypto/engine/lib

crypto/engine/lib:	$(LIBOBJ_crypto_engine)
	$(ARX) $(LIB_crypto_engine) $(LIBOBJ_crypto_engine)
	$(RANLIB) $(LIB_crypto_engine) || echo Never mind.
	@touch crypto/engine/lib

files: files_crypto_engine
files_crypto_engine:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_engine
links_crypto_engine:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_engine)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_engine)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_engine)

install: install_crypto_engine
install_crypto_engine:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_engine)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_engine
tags_crypto_engine:
	ctags $(SRC_crypto_engine)

tests: tests_crypto_engine
tests_crypto_engine:

lint: lint_crypto_engine
lint_crypto_engine:
	lint -DLINT $(INCLUDES_crypto_engine) $(SRC_crypto_engine)>crypto/engine/fluff

dclean: dclean_crypto_engine
dclean_crypto_engine:

clean: clean_crypto_engine
clean_crypto_engine:
	rm -f crypto/engine/*.o crypto/engine/*.d */*.o */*.d crypto/engine/*.obj crypto/engine/lib crypto/engine/tags crypto/engine/core crypto/engine/.pure crypto/engine/.nfs* crypto/engine/*.old crypto/engine/*.bak crypto/engine/fluff

.c.o:
	$(CC) $(CFLAGS_crypto_engine) $(CPPFLAGS) -c -o $@ $<
