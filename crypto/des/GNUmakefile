#
# OpenSSL/crypto/des/GNUmakefile
#

include crypto/des/Makefile
-include $(SRC_crypto_des:.c=.d)

crypto/des/%.o: crypto/des/%.c
	$(CC) $(CFLAGS_crypto_des) $(CPPFLAGS) -c -o $@ $<
crypto/des/%.o: crypto/des/%.s
	$(AS) $(ASFLAGS_crypto_des) -o $@ $<
crypto/des/%.s: crypto/des/%.S
	$(CPP_crypto_des) $(CPPFLAGS) -o $@ $<
