#
# OpenSSL/crypto/ts/GNUmakefile
#

include crypto/ts/Makefile
-include $(SRC_crypto_ts:.c=.d)

crypto/ts/%.o: crypto/ts/%.c
	$(CC) $(CFLAGS_crypto_ts) $(CPPFLAGS) -c -o $@ $<
