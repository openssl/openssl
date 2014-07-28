#
# OpenSSL/crypto/engine/Makefile
#

DIR_crypto_engine=	engine
INCLUDES_crypto_engine= -I.. -I$(TOP_crypto_engine) -I../../include

CFLAGS_crypto_engine= $(INCLUDES_crypto_engine) $(CFLAG)

GENERAL_crypto_engine=Makefile
TEST_crypto_engine= enginetest.c
APPS_crypto_engine=

LIB_crypto_engine=$(TOP_crypto_engine)/libcrypto.a
LIBSRC_crypto_engine= eng_err.c eng_lib.c eng_list.c eng_init.c eng_ctrl.c \
	eng_table.c eng_pkey.c eng_fat.c eng_all.c \
	tb_rsa.c tb_dsa.c tb_ecdsa.c tb_dh.c tb_ecdh.c tb_rand.c tb_store.c \
	tb_cipher.c tb_digest.c tb_pkmeth.c tb_asnmth.c \
	eng_openssl.c eng_cnf.c eng_dyn.c eng_cryptodev.c \
	eng_rdrand.c
LIBOBJ_crypto_engine= eng_err.o eng_lib.o eng_list.o eng_init.o eng_ctrl.o \
	eng_table.o eng_pkey.o eng_fat.o eng_all.o \
	tb_rsa.o tb_dsa.o tb_ecdsa.o tb_dh.o tb_ecdh.o tb_rand.o tb_store.o \
	tb_cipher.o tb_digest.o tb_pkmeth.o tb_asnmth.o \
	eng_openssl.o eng_cnf.o eng_dyn.o eng_cryptodev.o \
	eng_rdrand.o

SRC_crypto_engine= $(LIBSRC_crypto_engine)

EXHEADER_crypto_engine= engine.h
HEADER_crypto_engine=	$(EXHEADER_crypto_engine)

ALL_crypto_engine=    $(GENERAL_crypto_engine) $(SRC_crypto_engine) $(HEADER_crypto_engine)

top: top_crypto_engine
top_crypto_engine:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_engine) sub_all)

all: all_crypto_engine
all_crypto_engine:	lib

lib:	$(LIBOBJ_crypto_engine)
	$(ARX) $(LIB_crypto_engine) $(LIBOBJ_crypto_engine)
	$(RANLIB) $(LIB_crypto_engine) || echo Never mind.
	@touch lib

files: files_crypto_engine
files_crypto_engine:
	$(PERL) $(TOP_crypto_engine)/util/files.pl TOP=$(TOP_crypto_engine) Makefile >> $(TOP_crypto_engine)/MINFO

links: links_crypto_engine
links_crypto_engine:
	@$(PERL) $(TOP_crypto_engine)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_engine)
	@$(PERL) $(TOP_crypto_engine)/util/mklink.pl ../../test $(TEST_crypto_engine)
	@$(PERL) $(TOP_crypto_engine)/util/mklink.pl ../../apps $(APPS_crypto_engine)

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
	lint -DLINT $(INCLUDES_crypto_engine) $(SRC_crypto_engine)>fluff

dclean: dclean_crypto_engine
dclean_crypto_engine:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_engine
clean_crypto_engine:
	rm -f *.o *.d */*.o */*.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_engine) $(CPPFLAGS) -c -o $@ $<
