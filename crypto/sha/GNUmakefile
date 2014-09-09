#
# OpenSSL/crypto/sha/GNUmakefile
#

include crypto/sha/Makefile
-include $(SRC_crypto_sha:.c=.d)

crypto/sha/%.o: crypto/sha/%.c
	$(CC) $(CFLAGS_crypto_sha) $(CPPFLAGS) -c -o $@ $<
crypto/sha/%.o: crypto/sha/%.s
	$(AS) $(ASFLAGS_crypto_sha) -o $@ $<
crypto/sha/%.s: crypto/sha/%.S
	$(CPP_crypto_sha) $(CPPFLAGS) -o $@ $<
