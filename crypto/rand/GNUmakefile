#
# OpenSSL/crypto/rand/GNUmakefile
#

include crypto/rand/Makefile
-include $(SRC_crypto_rand:.c=.d)

crypto/rand/%.o: crypto/rand/%.c
	$(CC) $(CFLAGS_crypto_rand) $(CPPFLAGS) -c -o $@ $<
