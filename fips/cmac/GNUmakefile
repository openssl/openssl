#
# OpenSSL/fips/cmac/GNUmakefile
#

include fips/cmac/Makefile
-include $(SRC_fips_cmac:.c=.d)

fips/cmac/%.o: fips/cmac/%.c
	$(CC) $(CFLAGS_fips_cmac) $(CPPFLAGS) -c -o $@ $<
