/*
 * Copyright 1999-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_OPENSSLV_H
# define OPENSSL_OPENSSLV_H
# pragma once

# include <openssl/macros.h>
# if !OPENSSL_API_3
#  define HEADER_OPENSSLV_H
# endif

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * SECTION 1: VERSION DATA.  These will change for each release
 */

/*
 * Base version macros
 *
 * These macros express version number MAJOR.MINOR.PATCH exactly
 */
# define OPENSSL_VERSION_MAJOR  3
# define OPENSSL_VERSION_MINOR  0
# define OPENSSL_VERSION_PATCH  0

/*
 * Additional version information, defined only when used.
 *
 * These are also part of the new version scheme, but aren't part
 * of the version number itself.
 */

/* Could be: #define OPENSSL_VERSION_PRE_RELEASE "-alpha.1" */
# define OPENSSL_VERSION_PRE_RELEASE "-dev"
/* Could be: #define OPENSSL_VERSION_BUILD_METADATA "+fips" */
/* Could be: #define OPENSSL_VERSION_BUILD_METADATA "+vendor.1" */
# undef OPENSSL_VERSION_BUILD_METADATA

/*
 * Note: OPENSSL_VERSION_BUILD_METADATA will never be defined by
 * the OpenSSL Project, it's entirely reserved for others vendors
 */

/*
 * Absolute string versions of OPENSSL_VERSION_PRE_RELEASE and
 * OPENSSL_VERSION_BUILD_METADATA.  As opposed to those, which
 * may be undefined, these are guaranteed to have strings as
 * values.
 */

# ifdef OPENSSL_VERSION_PRE_RELEASE
#  define OPENSSL_VERSION_PRE_RELEASE_STR OPENSSL_VERSION_PRE_RELEASE
# else
#  define OPENSSL_VERSION_PRE_RELEASE_STR ""
# endif
# ifdef OPENSSL_VERSION_BUILD_METADATA
#  define OPENSSL_VERSION_BUILD_METADATA_STR OPENSSL_VERSION_BUILD_METADATA
# else
#  define OPENSSL_VERSION_BUILD_METADATA_STR ""
# endif

/*
 * Shared library version
 *
 * This is strictly to express ABI version, which may or may not
 * be related to the API version expressed with the macros above.
 * This is defined in free form.
 */
# define OPENSSL_SHLIB_VERSION 3

/*
 * SECTION 2: USEFUL MACROS AND FUNCTIONS
 */

/* For checking general API compatibility when preprocessing */
# define OPENSSL_VERSION_PREREQ(maj,min)                                \
    ((OPENSSL_VERSION_MAJOR << 16) + OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))

/* Helper macros for CPP string composition */
#   define OPENSSL_MSTR_HELPER(x) #x
#   define OPENSSL_MSTR(x) OPENSSL_MSTR_HELPER(x)

/*
 * These return the values of OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR,
 * OPENSSL_VERSION_PATCH, OPENSSL_VERSION_PRE_RELEASE and
 * OPENSSL_VERSION_BUILD_METADATA, respectively.
 */
unsigned int OPENSSL_version_major(void);
unsigned int OPENSSL_version_minor(void);
unsigned int OPENSSL_version_patch(void);
const char *OPENSSL_version_pre_release(void);
const char *OPENSSL_version_build_metadata(void);

/*
 * Macros to get the version in easily digested string form, both the short
 * "MAJOR.MINOR.PATCH" variant (where MAJOR, MINOR and PATCH are replaced
 * with the values from the corresponding OPENSSL_VERSION_ macros) and the
 * longer variant with OPENSSL_VERSION_PRE_RELEASE_STR and
 * OPENSSL_VERSION_BUILD_METADATA_STR appended.
 */
# define OPENSSL_VERSION_STR                    \
    OPENSSL_MSTR(OPENSSL_VERSION_MAJOR) "."     \
    OPENSSL_MSTR(OPENSSL_VERSION_MINOR) "."     \
    OPENSSL_MSTR(OPENSSL_VERSION_PATCH)
# define OPENSSL_FULL_VERSION_STR               \
    OPENSSL_VERSION_STR                         \
    OPENSSL_VERSION_PRE_RELEASE_STR             \
    OPENSSL_VERSION_BUILD_METADATA_STR

/*
 * SECTION 3: ADDITIONAL METADATA
 */
# define OPENSSL_RELEASE_DATE "xx XXX xxxx"
# define OPENSSL_VERSION_TEXT                                           \
    "OpenSSL " OPENSSL_FULL_VERSION_STR " " OPENSSL_RELEASE_DATE

/*
 * SECTION 4: BACKWARD COMPATIBILITY
 */
/* Synthesize OPENSSL_VERSION_NUMBER with the layout 0xMNN00PPSL */
# ifdef OPENSSL_VERSION_PRE_RELEASE
#  define _OPENSSL_VERSION_PRE_RELEASE 0x0
# else
#  define _OPENSSL_VERSION_PRE_RELEASE 0xf
# endif
# define OPENSSL_VERSION_NUMBER          \
    ( (OPENSSL_VERSION_MAJOR<<28)        \
      |(OPENSSL_VERSION_MINOR<<20)       \
      |(OPENSSL_VERSION_PATCH<<4)        \
      |_OPENSSL_VERSION_PRE_RELEASE )

# ifdef  __cplusplus
}
# endif
#endif                          /* OPENSSL_OPENSSLV_H */
