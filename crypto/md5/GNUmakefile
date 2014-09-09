#
# OpenSSL/crypto/md5/GNUmakefile
#

include crypto/md5/Makefile
-include $(SRC_crypto_md5:.c=.d)

crypto/md5/%.o: crypto/md5/%.c
	$(CC) $(CFLAGS_crypto_md5) $(CPPFLAGS) -c -o $@ $<
crypto/md5/%.o: crypto/md5/%.s
	$(AS) $(ASFLAGS_crypto_md5) -o $@ $<
crypto/md5/%.s: crypto/md5/%.S
	$(CPP_crypto_md5) $(CPPFLAGS) -o $@ $<
