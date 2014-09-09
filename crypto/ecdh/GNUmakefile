#
# OpenSSL/crypto/ecdh/GNUmakefile
#

include crypto/ecdh/Makefile
-include $(SRC_crypto_ecdh:.c=.d)

crypto/ecdh/%.o: crypto/ecdh/%.c
	$(CC) $(CFLAGS_crypto_ecdh) $(CPPFLAGS) -c -o $@ $<
