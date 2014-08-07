#
# OpenSSL/crypto/hmac/GNUmakefile
#

include crypto/hmac/Makefile
-include $(SRC_crypto_hmac:.c=.d)

crypto/hmac/%.o: crypto/hmac/%.c
	$(CC) $(CFLAGS_crypto_hmac) $(CPPFLAGS) -c -o $@ $<
