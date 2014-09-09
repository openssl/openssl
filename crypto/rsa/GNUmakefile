#
# OpenSSL/crypto/rsa/GNUmakefile
#

include crypto/rsa/Makefile
-include $(SRC_crypto_rsa:.c=.d)

crypto/rsa/%.o: crypto/rsa/%.c
	$(CC) $(CFLAGS_crypto_rsa) $(CPPFLAGS) -c -o $@ $<
