#ifdef FIPS
# include "fips_err.c"
#else
static void *dummy=&dummy;
#endif
