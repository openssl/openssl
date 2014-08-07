#
# OpenSSL/fips/dsa/GNUmakefile
#

include fips/dsa/Makefile
-include $(SRC_fips_dsa:.c=.d)

fips/dsa/%.o: fips/dsa/%.c
	$(CC) $(CFLAGS_fips_dsa) $(CPPFLAGS) -c -o $@ $<
