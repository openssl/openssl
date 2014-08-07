#
# OpenSSL/crypto/rc5/GNUmakefile
#

include crypto/rc5/Makefile
-include $(SRC_crypto_rc5:.c=.d)

crypto/rc5/%.o: crypto/rc5/%.c
	$(CC) $(CFLAGS_crypto_rc5) $(CPPFLAGS) -c -o $@ $<
crypto/rc5/%.o: crypto/rc5/%.s
	$(AS) $(ASFLAGS_crypto_rc5) -o $@ $<
crypto/rc5/%.s: crypto/rc5/%.S
	$(CPP_crypto_rc5) $(CPPFLAGS) -o $@ $<
