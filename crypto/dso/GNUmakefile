#
# OpenSSL/crypto/dso/GNUmakefile
#

include crypto/dso/Makefile
-include $(SRC_crypto_dso:.c=.d)

crypto/dso/%.o: crypto/dso/%.c
	$(CC) $(CFLAGS_crypto_dso) $(CPPFLAGS) -c -o $@ $<
