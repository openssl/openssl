#
# OpenSSL/fips/rand/GNUmakefile
#

include fips/rand/Makefile
-include $(SRC_fips_rand:.c=.d)

fips/rand/%.o: fips/rand/%.c
	$(CC) $(CFLAGS_fips_rand) $(CPPFLAGS) -c -o $@ $<
