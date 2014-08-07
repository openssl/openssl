#
# OpenSSL/crypto/ripemd/GNUmakefile
#

include crypto/ripemd/Makefile
-include $(SRC_crypto_ripemd:.c=.d)

crypto/ripemd/%.o: crypto/ripemd/%.c
	$(CC) $(CFLAGS_crypto_ripemd) $(CPPFLAGS) -c -o $@ $<
crypto/ripemd/%.o: crypto/ripemd/%.s
	$(AS) $(ASFLAGS_crypto_ripemd) -o $@ $<
crypto/ripemd/%.s: crypto/ripemd/%.S
	$(CPP_crypto_ripemd) $(CPPFLAGS) -o $@ $<
