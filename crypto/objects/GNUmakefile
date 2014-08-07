#
# OpenSSL/crypto/objects/GNUmakefile
#

include crypto/objects/Makefile
-include $(SRC_crypto_objects:.c=.d)

crypto/objects/%.o: crypto/objects/%.c
	$(CC) $(CFLAGS_crypto_objects) $(CPPFLAGS) -c -o $@ $<
