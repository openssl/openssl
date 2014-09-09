#
# OpenSSL/crypto/cms/GNUmakefile
#

include crypto/cms/Makefile
-include $(SRC_crypto_cms:.c=.d)

crypto/cms/%.o: crypto/cms/%.c
	$(CC) $(CFLAGS_crypto_cms) $(CPPFLAGS) -c -o $@ $<
