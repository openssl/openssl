#
# OpenSSL/crypto/bf/GNUmakefile
#

include crypto/bf/Makefile
-include $(SRC_crypto_bf:.c=.d)

crypto/bf/%.o: crypto/bf/%.c
	$(CC) $(CFLAGS_crypto_bf) $(CPPFLAGS) -c -o $@ $<
crypto/bf/%.o: crypto/bf/%.s
	$(AS) $(ASFLAGS_crypto_bf) -o $@ $<
crypto/bf/%.s: crypto/bf/%.S
	$(CPP_crypto_bf) $(CPPFLAGS) -o $@ $<
