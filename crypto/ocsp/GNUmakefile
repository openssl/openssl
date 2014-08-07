#
# OpenSSL/crypto/ocsp/GNUmakefile
#

include crypto/ocsp/Makefile
-include $(SRC_crypto_ocsp:.c=.d)

crypto/ocsp/%.o: crypto/ocsp/%.c
	$(CC) $(CFLAGS_crypto_ocsp) $(CPPFLAGS) -c -o $@ $<
