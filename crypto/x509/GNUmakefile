#
# OpenSSL/crypto/x509/GNUmakefile
#

include crypto/x509/Makefile
-include $(SRC_crypto_x509:.c=.d)

crypto/x509/%.o: crypto/x509/%.c
	$(CC) $(CFLAGS_crypto_x509) $(CPPFLAGS) -c -o $@ $<
