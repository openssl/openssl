#
# OpenSSL/crypto/asn1/GNUmakefile
#

include crypto/asn1/Makefile
-include $(SRC_crypto_asn1:.c=.d)

crypto/asn1/%.o: crypto/asn1/%.c
	$(CC) $(CFLAGS_crypto_asn1) $(CPPFLAGS) -c -o $@ $<
