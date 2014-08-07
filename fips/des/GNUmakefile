#
# OpenSSL/fips/des/GNUmakefile
#

include fips/des/Makefile
-include $(SRC_fips_des:.c=.d)

fips/des/%.o: fips/des/%.c
	$(CC) $(CFLAGS_fips_des) $(CPPFLAGS) -c -o $@ $<
fips/des/%.o: fips/des/%.s
	$(AS) $(ASFLAGS_fips_des) -o $@ $<
