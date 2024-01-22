FIPS Indicator Design
=====================

This is a simple FIPS indicator API design based on a set of thread-local
bitflags, which all start out set to 1. A bitflag is cleared if an operation is
performed in violation of the requirements of an indicator.

This enables ergonomic usage because it allows you to perform a sequence of
cryptographic operations and then test if any of those operations were performed
in violation of the requirements of FIPS at the end, rather than testing every
single operation.

```c
/*
 * The set of different indicators which can be reported.
 */
#define OSSL_FIPS_INDICATOR_FIPS_140_2      (1UL << 0)
#define OSSL_FIPS_INDICATOR_FIPS_140_3      (1UL << 1)

/*
 * Retrieve the thread-local FIPS indicator flags. The returned value is a
 * bitmask formed from OSSL_FIPS_INDICATOR values. Undefined bits (which have
 * yet to be assigned) are 1 by default.
 *
 * If a bit is set to 1, this indicates that all operations occurring since that
 * indicator bit was reset were performed in compliance with the requirements
 * of the given indicator bit. If a bit is cleared to 0, this means that at
 * least one operation in violation of the requirements of that indicator bit
 * has been performed since the indicators were reset.
 *
 * The indicator flags are thread-local, and therefore reflect operations
 * performed on the current thread.
 */
uint64_t OPENSSL_get_fips_indicators(void);

/*
 * Clears zero or more FIPS indicator bits, transitioning them to 0. This
 * is to be used when an algorithm is executed which does not comply with
 * the requirements of an indicator bit. This function is idempotent.
 * The argument is a bitmask of the indicator bits which should be cleared.
 */
void OPENSSL_clear_fips_indicators(uint64_t indicators);

/*
 * Resets (sets to 1) zero or more FIPS indicator bits. This is to be used to
 * restore an indicator bit before performing more cryptographic algorithm
 * invocations, so that the compliance of those invocations can subsequently be
 * tested. This function is idempotent. The argument is a bitmask of the
 * indicator bits which should be set to 1.
 */
void OPENSSL_reset_fips_indicators(uint64_t indicators);

/*
 * Resets (sets to 1) all FIPS indicators.
 */
void OPENSSL_reset_all_fips_indicators(void);
```

Questions to be resolved
------------------------

Questions to be resolved in the above design:

* This is a thread-local design. It is fast and pragmatic and actually quite
  "ergonomic" to use. But do things need to be `OSSL_LIB_CTX`-local rather than
  thread-local?

  * Adding an `OSSL_LIB_CTX` argument to the above functions would be a simple
    adaptation and seems viable, but would need to determine
    performance/locking/cache contention implications.

* The chosen set of bit flags:
  * The exact set of 'categories' of indicator will need to be determined.
  * Should there be separate indicators for different things?
  * Or just one big "FIPS" indicator?
  * Do we need separate indicators for 140-2 and 140-3?
  * What about other national standards?
