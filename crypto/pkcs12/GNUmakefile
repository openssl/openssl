#
# OpenSSL/crypto/pkcs12/GNUmakefile
#

include crypto/pkcs12/Makefile
-include $(SRC_crypto_pkcs12:.c=.d)

crypto/pkcs12/%.o: crypto/pkcs12/%.c
	$(CC) $(CFLAGS_crypto_pkcs12) $(CPPFLAGS) -c -o $@ $<
