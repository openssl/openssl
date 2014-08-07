#
# OpenSSL/crypto/srp/GNUmakefile
#

include crypto/srp/Makefile
-include $(SRC_crypto_srp:.c=.d)

crypto/srp/%.o: crypto/srp/%.c
	$(CC) $(CFLAGS_crypto_srp) $(CPPFLAGS) -c -o $@ $<
