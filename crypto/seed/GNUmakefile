#
# OpenSSL/crypto/seed/GNUmakefile
#

include crypto/seed/Makefile
-include $(SRC_crypto_seed:.c=.d)

crypto/seed/%.o: crypto/seed/%.c
	$(CC) $(CFLAGS_crypto_seed) $(CPPFLAGS) -c -o $@ $<
crypto/seed/%.s: crypto/seed/%.S
	$(CPP_crypto_seed) $(CPPFLAGS) -o $@ $<
