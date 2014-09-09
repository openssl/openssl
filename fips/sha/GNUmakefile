#
# OpenSSL/fips/sha/GNUmakefile
#

include fips/sha/Makefile

ifdef FIPSCANISTERONLY
include fips_standalone_sha1.mk
else ifndef FIPSLIBDIR
include fips_standalone_sha1.mk
else
endif

-include $(SRC_fips_sha:.c=.d)

fips/sha/%.o: fips/sha/%.c
	$(CC) $(CFLAGS_fips_sha) $(CPPFLAGS) -c -o $@ $<
fips/sha/%.o: fips/sha/%.s
	$(AS) $(ASFLAGS_fips_sha) -o $@ $<
