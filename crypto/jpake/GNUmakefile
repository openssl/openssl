#
# OpenSSL/crypto/jpake/GNUmakefile
#

include crypto/jpake/Makefile
-include $(SRC_crypto_jpake:.c=.d)

crypto/jpake/%.o: crypto/jpake/%.c
	$(CC) $(CFLAGS_crypto_jpake) $(CPPFLAGS) -c -o $@ $<
