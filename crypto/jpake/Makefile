DIR=jpake
TOP=../..

CFLAGS= $(INCLUDES) $(CFLAG)

LIB=$(TOP)/libcrypto.a
LIBOBJ=jpake.o jpake_err.o
LIBSRC=jpake.c jpake_err.c

EXHEADER=jpake.h
TEST=jpaketest.c

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib: lib_arx_common

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)

install: install_common

depend: depend_common

dclean: dclean_common

clean: clean_common
	rm -f *.s des

jpaketest: top jpaketest.c $(LIB)
	$(CC) $(CFLAGS) -Wall -Werror -g -o jpaketest jpaketest.c $(LIB)

include $(TOP)/Makefile.common

# DO NOT DELETE THIS LINE -- make depend depends on it.

jpake.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
jpake.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
jpake.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
jpake.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
jpake.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
jpake.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
jpake.o: ../../include/openssl/symhacks.h jpake.c jpake.h
jpake_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
jpake_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
jpake_err.o: ../../include/openssl/err.h ../../include/openssl/jpake.h
jpake_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
jpake_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
jpake_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
jpake_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
jpake_err.o: jpake_err.c
