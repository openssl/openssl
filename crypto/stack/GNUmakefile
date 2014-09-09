#
# OpenSSL/crypto/stack/GNUmakefile
#

include crypto/stack/Makefile
-include $(SRC_crypto_stack:.c=.d)

crypto/stack/%.o: crypto/stack/%.c
	$(CC) $(CFLAGS_crypto_stack) $(CPPFLAGS) -c -o $@ $<
