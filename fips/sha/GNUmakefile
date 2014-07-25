#
# OpenSSL/fips/sha/GNUmakefile
#

TOP_fips_sha= ../..
include $(TOP_fips_sha)/configure.mk
include Makefile

ifdef FIPSCANISTERONLY
include fips_standalone_sha1.mk
else ifndef FIPSLIBDIR
include fips_standalone_sha1.mk
else
endif

-include $(SRC_fips_sha:.c=.d)
