#
# OpenSSL/crypto/ui/GNUmakefile
#

include crypto/ui/Makefile
-include $(SRC_crypto_ui:.c=.d)

crypto/ui/%.o: crypto/ui/%.c
	$(CC) $(CFLAGS_crypto_ui) $(CPPFLAGS) -c -o $@ $<
