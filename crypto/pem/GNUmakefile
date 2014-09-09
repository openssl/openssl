#
# OpenSSL/crypto/pem/GNUmakefile
#

include crypto/pem/Makefile
-include $(SRC_crypto_pem:.c=.d)

crypto/pem/%.o: crypto/pem/%.c
	$(CC) $(CFLAGS_crypto_pem) $(CPPFLAGS) -c -o $@ $<
