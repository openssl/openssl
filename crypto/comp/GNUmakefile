#
# OpenSSL/crypto/comp/GNUmakefile
#

include crypto/comp/Makefile
-include $(SRC_crypto_comp:.c=.d)

crypto/comp/%.o: crypto/comp/%.c
	$(CC) $(CFLAGS_crypto_comp) $(CPPFLAGS) -c -o $@ $<
