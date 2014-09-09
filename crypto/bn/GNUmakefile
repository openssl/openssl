#
# OpenSSL/crypto/bn/GNUmakefile
#

include crypto/bn/Makefile
-include $(SRC_crypto_bn:.c=.d)

crypto/bn/%.o: crypto/bn/%.c
	$(CC) $(CFLAGS_crypto_bn) $(CPPFLAGS) -c -o $@ $<
crypto/bn/%.o: crypto/bn/%.s
	$(AS) $(ASFLAGS_crypto_bn) -o $@ $<
crypto/bn/%.s: crypto/bn/%.S
	$(CPP_crypto_bn) $(CPPFLAGS) -o $@ $<
