#
# OpenSSL/crypto/conf/GNUmakefile
#

include crypto/conf/Makefile
-include $(SRC_crypto_conf:.c=.d)

crypto/conf/%.o: crypto/conf/%.c
	$(CC) $(CFLAGS_crypto_conf) $(CPPFLAGS) -c -o $@ $<
