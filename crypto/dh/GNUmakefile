#
# OpenSSL/crypto/dh/GNUmakefile
#

include crypto/dh/Makefile
-include $(SRC_crypto_dh:.c=.d)

crypto/dh/%.o: crypto/dh/%.c
	$(CC) $(CFLAGS_crypto_dh) $(CPPFLAGS) -c -o $@ $<
