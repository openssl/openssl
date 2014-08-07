#
# OpenSSL/crypto/whrlpool/GNUmakefile
#

include crypto/whrlpool/Makefile
-include $(SRC_crypto_whrlpool:.c=.d)

crypto/whrlpool/%.o: crypto/whrlpool/%.c
	$(CC) $(CFLAGS_crypto_whrlpool) $(CPPFLAGS) -c -o $@ $<
crypto/whrlpool/%.o: crypto/whrlpool/%.s
	$(AS) $(ASFLAGS_crypto_whrlpool) -o $@ $<
crypto/whrlpool/%.s: crypto/whrlpool/%.S
	$(CPP_crypto_whrlpool) $(CPPFLAGS) -o $@ $<
