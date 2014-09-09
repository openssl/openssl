#
# OpenSSL/crypto/md4/GNUmakefile
#

include crypto/md4/Makefile
-include $(SRC_crypto_md4:.c=.d)

crypto/md4/%.o: crypto/md4/%.c
	$(CC) $(CFLAGS_crypto_md4) $(CPPFLAGS) -c -o $@ $<
crypto/md4/%.s: crypto/md4/%.S
	$(CPP_crypto_md4) $(CPPFLAGS) -o $@ $<
