#
# OpenSSL/crypto/cast/GNUmakefile
#

include crypto/cast/Makefile
-include $(SRC_crypto_cast:.c=.d)

crypto/cast/%.o: crypto/cast/%.c
	$(CC) $(CFLAGS_crypto_cast) $(CPPFLAGS) -c -o $@ $<
crypto/cast/%.o: crypto/cast/%.s
	$(AS) $(ASFLAGS_crypto_cast) -o $@ $<
crypto/cast/%.s: crypto/cast/%.S
	$(CPP_crypto_cast) $(CPPFLAGS) -o $@ $<
