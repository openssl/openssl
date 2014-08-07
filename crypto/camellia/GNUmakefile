#
# OpenSSL/crypto/camellia/GNUmakefile
#

include crypto/camellia/Makefile
-include $(SRC_crypto_camellia:.c=.d)

crypto/camellia/%.o: crypto/camellia/%.c
	$(CC) $(CFLAGS_crypto_camellia) $(CPPFLAGS) -c -o $@ $<
crypto/camellia/%.o: crypto/camellia/%.s
	$(AS) $(ASFLAGS_crypto_camellia) -o $@ $<
crypto/camellia/%.s: crypto/camellia/%.S
	$(CPP_crypto_camellia) $(CPPFLAGS) -o $@ $<
