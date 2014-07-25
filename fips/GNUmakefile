#
# OpenSSL/fips/GNUmakefile
#

TOP_fips= ..
include $(TOP_fips)/configure.mk
include Makefile

ifdef FIPSCANISTERONLY
all_fips: subdirs_fips lib
else ifndef FIPSLIBDIR
all_fips: subdirs_fips lib fips_premain_dso$(EXE_EXT)
else
all_fips: lib fips_premain_dso$(EXE_EXT) fips_standalone_sha1$(EXE_EXT)
include fips_standalone_sha1.mk
endif

-include $(SRC_fips:.c=.d)
