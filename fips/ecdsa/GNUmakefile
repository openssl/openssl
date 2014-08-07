#
# OpenSSL/fips/ecdsa/GNUmakefile
#

include fips/ecdsa/Makefile
-include $(SRC_fips_ecdsa:.c=.d)

fips/ecdsa/%.o: fips/ecdsa/%.c
	$(CC) $(CFLAGS_fips_ecdsa) $(CPPFLAGS) -c -o $@ $<
