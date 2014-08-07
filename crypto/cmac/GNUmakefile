#
# OpenSSL/crypto/cmac/GNUmakefile
#

include crypto/cmac/Makefile
-include $(SRC_crypto_cmac:.c=.d)

crypto/cmac/%.o: crypto/cmac/%.c
	$(CC) $(CFLAGS_crypto_cmac) $(CPPFLAGS) -c -o $@ $<
