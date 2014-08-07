#
# OpenSSL/fips/dh/GNUmakefile
#

include fips/dh/Makefile
-include $(SRC_fips_dh:.c=.d)

fips/dh/%.o: fips/dh/%.c
	$(CC) $(CFLAGS_fips_dh) $(CPPFLAGS) -c -o $@ $<
