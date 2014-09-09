#
# OpenSSL/crypto/rc4/GNUmakefile
#

include crypto/rc4/Makefile
-include $(SRC_crypto_rc4:.c=.d)

crypto/rc4/%.o: crypto/rc4/%.c
	$(CC) $(CFLAGS_crypto_rc4) $(CPPFLAGS) -c -o $@ $<
crypto/rc4/%.o: crypto/rc4/%.s
	$(AS) $(ASFLAGS_crypto_rc4) -o $@ $<
crypto/rc4/%.s: crypto/rc4/%.S
	$(CPP_crypto_rc4) $(CPPFLAGS) -o $@ $<
