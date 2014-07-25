#
# OpenSSL/fips/GNUmakefile
#

TOP_fips= ..
include $(TOP_fips)/configure.mk
include Makefile

ifdef FIPSCANISTERONLY
else ifndef FIPSLIBDIR
else
include fips_standalone_sha1.mk
endif

-include $(SRC_fips:.c=.d)
