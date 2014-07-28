DIR_crypto_jpake=jpake

CFLAGS_crypto_jpake= $(INCLUDES) $(CFLAG)

LIB_crypto_jpake=$(TOP_crypto_jpake)/libcrypto.a
LIBOBJ_crypto_jpake=jpake.o jpake_err.o
LIBSRC_crypto_jpake=jpake.c jpake_err.c
SRC_crypto_jpake= $(LIBSRC_crypto_jpake)

EXHEADER_crypto_jpake=jpake.h
TEST_crypto_jpake=jpaketest.c

top: top_crypto_jpake
top_crypto_jpake:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_jpake) sub_all)

all: all_crypto_jpake
all_crypto_jpake:	lib

lib:	$(LIBOBJ_crypto_jpake)
	$(ARX) $(LIB_crypto_jpake) $(LIBOBJ_crypto_jpake)
	$(RANLIB) $(LIB_crypto_jpake) || echo Never mind.
	@touch lib

links: links_crypto_jpake
links_crypto_jpake:
	@$(PERL) $(TOP_crypto_jpake)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_jpake)
	@$(PERL) $(TOP_crypto_jpake)/util/mklink.pl ../../test $(TEST_crypto_jpake)

install: install_crypto_jpake
install_crypto_jpake:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_jpake)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

dclean: dclean_crypto_jpake
dclean_crypto_jpake:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_jpake
clean_crypto_jpake:
	rm -f *.s *.o *.d *.obj des lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_jpake) $(CPPFLAGS) -c -o $@ $<
