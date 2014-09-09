#
# OpenSSL/crypto/engine/GNUmakefile
#

include crypto/engine/Makefile
-include $(SRC_crypto_engine:.c=.d)

crypto/engine/%.o: crypto/engine/%.c
	$(CC) $(CFLAGS_crypto_engine) $(CPPFLAGS) -c -o $@ $<
