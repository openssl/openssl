#
# OpenSSL/crypto/rc2/GNUmakefile
#

include crypto/rc2/Makefile
-include $(SRC_crypto_rc2:.c=.d)

crypto/rc2/%.o: crypto/rc2/%.c
	$(CC) $(CFLAGS_crypto_rc2) $(CPPFLAGS) -c -o $@ $<
