#
# OpenSSL/fips/hmac/GNUmakefile
#

include fips/hmac/Makefile
-include $(SRC_fips_hmac:.c=.d)

fips/hmac/%.o: fips/hmac/%.c
	$(CC) $(CFLAGS_fips_hmac) $(CPPFLAGS) -c -o $@ $<
