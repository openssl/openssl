#
# OpenSSL/crypto/lhash/GNUmakefile
#

include crypto/lhash/Makefile
-include $(SRC_crypto_lhash:.c=.d)

crypto/lhash/%.o: crypto/lhash/%.c
	$(CC) $(CFLAGS_crypto_lhash) $(CPPFLAGS) -c -o $@ $<
