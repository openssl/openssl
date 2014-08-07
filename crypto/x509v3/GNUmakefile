#
# OpenSSL/crypto/x509v3/GNUmakefile
#

include crypto/x509v3/Makefile
-include $(SRC_crypto_x509v3:.c=.d)

crypto/x509v3/%.o: crypto/x509v3/%.c
	$(CC) $(CFLAGS_crypto_x509v3) $(CPPFLAGS) -c -o $@ $<
