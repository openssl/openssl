#
# OpenSSL/crypto/aes/GNUmakefile
#

include crypto/aes/Makefile
-include $(SRC_crypto_aes:.c=.d)

crypto/aes/%.o: crypto/aes/%.c
	$(CC) $(CFLAGS_crypto_aes) $(CPPFLAGS) -c -o $@ $<
crypto/aes/%.o: crypto/aes/%.s
	$(AS) $(ASFLAGS_crypto_aes) -o $@ $<
crypto/aes/%.s: crypto/aes/%.S
	$(CPP_crypto_aes) $(CPPFLAGS) -o $@ $<
