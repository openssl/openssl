#
# OpenSSL/crypto/ecdsa/GNUmakefile
#

include crypto/ecdsa/Makefile
-include $(SRC_crypto_ecdsa:.c=.d)

crypto/ecdsa/%.o: crypto/ecdsa/%.c
	$(CC) $(CFLAGS_crypto_ecdsa) $(CPPFLAGS) -c -o $@ $<
