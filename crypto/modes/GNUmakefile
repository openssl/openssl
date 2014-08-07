#
# OpenSSL/crypto/modes/GNUmakefile
#

include crypto/modes/Makefile
-include $(SRC_crypto_modes:.c=.d)

crypto/modes/%.o: crypto/modes/%.c
	$(CC) $(CFLAGS_crypto_modes) $(CPPFLAGS) -c -o $@ $<
crypto/modes/%.o: crypto/modes/%.s
	$(AS) $(ASFLAGS_crypto_modes) -o $@ $<
