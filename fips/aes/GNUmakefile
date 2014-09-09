#
# OpenSSL/fips/aes/GNUmakefile
#

include fips/aes/Makefile
-include $(SRC_fips_aes:.c=.d)

fips/aes/%.o: fips/aes/%.c
	$(CC) $(CFLAGS_fips_aes) $(CPPFLAGS) -c -o $@ $<
fips/aes/%.o: fips/aes/%.s
	$(AS) $(ASFLAGS_fips_aes) -o $@ $<
