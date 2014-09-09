#
# OpenSSL/fips/ecdh/GNUmakefile
#

include fips/ecdh/Makefile
-include $(SRC_fips_ecdh:.c=.d)

fips/ecdh/%.o: fips/ecdh/%.c
	$(CC) $(CFLAGS_fips_ecdh) $(CPPFLAGS) -c -o $@ $<
