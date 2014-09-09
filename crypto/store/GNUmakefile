#
# OpenSSL/crypto/store/GNUmakefile
#

include crypto/store/Makefile
-include $(SRC_crypto_store:.c=.d)

crypto/store/%.o: crypto/store/%.c
	$(CC) $(CFLAGS_crypto_store) $(CPPFLAGS) -c -o $@ $<
