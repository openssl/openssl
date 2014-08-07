#
# OpenSSL/crypto/idea/GNUmakefile
#

include crypto/idea/Makefile
-include $(SRC_crypto_idea:.c=.d)

crypto/idea/%.o: crypto/idea/%.c
	$(CC) $(CFLAGS_crypto_idea) $(CPPFLAGS) -c -o $@ $<
