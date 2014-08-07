#
# OpenSSL/crypto/bio/GNUmakefile
#

include crypto/bio/Makefile
-include $(SRC_crypto_bio:.c=.d)

crypto/bio/%.o: crypto/bio/%.c
	$(CC) $(CFLAGS_crypto_bio) $(CPPFLAGS) -c -o $@ $<
