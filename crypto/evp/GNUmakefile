#
# OpenSSL/crypto/evp/GNUmakefile
#

include crypto/evp/Makefile
-include $(SRC_crypto_evp:.c=.d)

crypto/evp/%.o: crypto/evp/%.c
	$(CC) $(CFLAGS_crypto_evp) $(CPPFLAGS) -c -o $@ $<
