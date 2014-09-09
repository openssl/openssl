#
# OpenSSL/crypto/err/GNUmakefile
#

include crypto/err/Makefile
-include $(SRC_crypto_err:.c=.d)

crypto/err/%.o: crypto/err/%.c
	$(CC) $(CFLAGS_crypto_err) $(CPPFLAGS) -c -o $@ $<
