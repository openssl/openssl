#
# OpenSSL/crypto/krb5/GNUmakefile
#

include crypto/krb5/Makefile
-include $(SRC_crypto_krb5:.c=.d)

crypto/krb5/%.o: crypto/krb5/%.c
	$(CC) $(CFLAGS_crypto_krb5) $(CPPFLAGS) -c -o $@ $<
