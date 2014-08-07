#
# OpenSSL/crypto/txt_db/GNUmakefile
#

include crypto/txt_db/Makefile
-include $(SRC_crypto_txt_db:.c=.d)

crypto/txt_db/%.o: crypto/txt_db/%.c
	$(CC) $(CFLAGS_crypto_txt_db) $(CPPFLAGS) -c -o $@ $<
