#
# OpenSSL/crypto/pkcs7/GNUmakefile
#

include crypto/pkcs7/Makefile
-include $(SRC_crypto_pkcs7:.c=.d)

crypto/pkcs7/%.o: crypto/pkcs7/%.c
	$(CC) $(CFLAGS_crypto_pkcs7) $(CPPFLAGS) -c -o $@ $<
