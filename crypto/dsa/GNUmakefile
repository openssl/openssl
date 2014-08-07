#
# OpenSSL/crypto/dsa/GNUmakefile
#

include crypto/dsa/Makefile
-include $(SRC_crypto_dsa:.c=.d)

crypto/dsa/%.o: crypto/dsa/%.c
	$(CC) $(CFLAGS_crypto_dsa) $(CPPFLAGS) -c -o $@ $<
