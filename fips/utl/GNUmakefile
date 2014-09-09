#
# OpenSSL/fips/utl/GNUmakefile
#

include fips/utl/Makefile
-include $(SRC_fips_utl:.c=.d)

fips/utl/%.o: fips/utl/%.c
	$(CC) $(CFLAGS_fips_utl) $(CPPFLAGS) -c -o $@ $<
