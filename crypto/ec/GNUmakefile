#
# OpenSSL/crypto/ec/GNUmakefile
#

include crypto/ec/Makefile
-include $(SRC_crypto_ec:.c=.d)

crypto/ec/%.o: crypto/ec/%.c
	$(CC) $(CFLAGS_crypto_ec) $(CPPFLAGS) -c -o $@ $<
crypto/ec/%.o: crypto/ec/%.s
	$(AS) $(ASFLAGS_crypto_ec) -o $@ $<
