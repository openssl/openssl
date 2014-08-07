#
# OpenSSL/crypto/mdc2/GNUmakefile
#

include crypto/mdc2/Makefile
-include $(SRC_crypto_mdc2:.c=.d)

crypto/mdc2/%.o: crypto/mdc2/%.c
	$(CC) $(CFLAGS_crypto_mdc2) $(CPPFLAGS) -c -o $@ $<
