/*
 *
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CONFIGURATION_H
# define OPENSSL_CONFIGURATION_H
# pragma once

# ifdef  __cplusplus
extern "C" {
# endif

# ifdef OPENSSL_ALGORITHM_DEFINES
#  error OPENSSL_ALGORITHM_DEFINES no longer supported
# endif

/*
 * OpenSSL was configured with the following options:
 */

#ifndef OPENSSL_CONFIGURED_API
# define OPENSSL_CONFIGURED_API (3 * 10000 + 0 * 100)
#endif
#ifndef OPENSSL_API_COMPAT
# define OPENSSL_API_COMPAT 0x10100000
#endif
#ifndef OPENSSL_THREADS
# define OPENSSL_THREADS
#endif
#ifndef OPENSSL_RAND_SEED_OS
# define OPENSSL_RAND_SEED_OS
#endif
#ifndef OPENSSL_NO_ASAN
# define OPENSSL_NO_ASAN
#endif
#ifndef OPENSSL_NO_ASM
# define OPENSSL_NO_ASM
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
# define OPENSSL_NO_CRYPTO_MDEBUG
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
# define OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
#endif
#ifndef OPENSSL_NO_DEVCRYPTOENG
# define OPENSSL_NO_DEVCRYPTOENG
#endif
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
# define OPENSSL_NO_EC_NISTP_64_GCC_128
#endif
#ifndef OPENSSL_NO_EGD
# define OPENSSL_NO_EGD
#endif
#ifndef OPENSSL_NO_EXTERNAL_TESTS
# define OPENSSL_NO_EXTERNAL_TESTS
#endif
#ifndef OPENSSL_NO_FUZZ_AFL
# define OPENSSL_NO_FUZZ_AFL
#endif
#ifndef OPENSSL_NO_FUZZ_LIBFUZZER
# define OPENSSL_NO_FUZZ_LIBFUZZER
#endif
#ifndef OPENSSL_NO_HEARTBEATS
# define OPENSSL_NO_HEARTBEATS
#endif
#ifndef OPENSSL_NO_MSAN
# define OPENSSL_NO_MSAN
#endif
#ifndef OPENSSL_NO_SCTP
# define OPENSSL_NO_SCTP
#endif
#ifndef OPENSSL_NO_SSL_TRACE
# define OPENSSL_NO_SSL_TRACE
#endif
#ifndef OPENSSL_NO_SSL3
# define OPENSSL_NO_SSL3
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
# define OPENSSL_NO_SSL3_METHOD
#endif
#ifndef OPENSSL_NO_UBSAN
# define OPENSSL_NO_UBSAN
#endif
#ifndef OPENSSL_NO_UNIT_TEST
# define OPENSSL_NO_UNIT_TEST
#endif
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
# define OPENSSL_NO_WEAK_SSL_CIPHERS
#endif
#ifndef OPENSSL_NO_STATIC_ENGINE
# define OPENSSL_NO_STATIC_ENGINE
#endif
#ifndef OPENSSL_NO_AFALGENG
# define OPENSSL_NO_AFALGENG
#endif

/* Generate 80386 code? */
/* #undef OSSL_PROCESSOR_I386 */

/*
 * The following are cipher-specific, but are part of the public API.
 */
# if !defined(OPENSSL_SYS_UEFI)
/* #undef BN_LLONG */
/* Only one for the following should be defined */
# undef SIXTY_FOUR_BIT_LONG
# define SIXTY_FOUR_BIT_LONG
# undef SIXTY_FOUR_BIT
/* #undef SIXTY_FOUR_BIT */
# undef THIRTY_TWO_BIT
/* #undef THIRTY_TWO_BIT */
# endif

# define RC4_INT unsigned int

# ifdef  __cplusplus
}
# endif

#endif                          /* OPENSSL_CONFIGURATION_H */
