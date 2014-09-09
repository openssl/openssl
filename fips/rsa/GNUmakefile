#
# OpenSSL/fips/rsa/GNUmakefile
#

include fips/rsa/Makefile
-include $(SRC_fips_rsa:.c=.d)

fips/rsa/%.o: fips/rsa/%.c
	$(CC) $(CFLAGS_fips_rsa) $(CPPFLAGS) -c -o $@ $<
