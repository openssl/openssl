#
# OpenSSL/crypto/buffer/GNUmakefile
#

include crypto/buffer/Makefile
-include $(SRC_crypto_buffer:.c=.d)

crypto/buffer/%.o: crypto/buffer/%.c
	$(CC) $(CFLAGS_crypto_buffer) $(CPPFLAGS) -c -o $@ $<
