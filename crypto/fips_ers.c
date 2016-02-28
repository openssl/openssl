#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
NON_EMPTY_TRANSLATION_UNIT
#else
# include "fips_err.h"
#endif
