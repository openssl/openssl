/*
 * Copyright 1999-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_OPENSSLV_H
# define HEADER_OPENSSLV_H

# include <openssl/opensslconf.h>

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

/*
 * Sometimes OPENSSSL_NO_xxx ends up with an empty file and some compilers
 * don't like that.  This will hopefully silence them.
 */
# define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

/*
 * Applications should use -DOPENSSL_API_COMPAT=<version> to suppress the
 * declarations of functions deprecated in or before <version>.  If this is
 * undefined, the value of the macro OPENSSL_API_MIN from opensslconf.h
 * is the default.
 *
 * For any version number up until version 1.1.x, <version> is expected to be
 * the calculated version number 0xMNNFFPPSL.  For version numbers 3.0.0 and
 * on, <version> is expected to be only the major version number (i.e. 3 for
 * version 3.0.0).
 */
# ifndef DECLARE_DEPRECATED
#  define DECLARE_DEPRECATED(f)   f;
#  ifdef __GNUC__
#   if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)
#    undef DECLARE_DEPRECATED
#    define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#   endif
#  elif defined(__SUNPRO_C)
#   if (__SUNPRO_C >= 0x5130)
#    undef DECLARE_DEPRECATED
#    define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#   endif
#  endif
# endif

/*
 * We convert the OPENSSL_API_COMPAT value to an API level.  The API level
 * is the major version number for 3.0.0 and on.  For earlier versions, it
 * uses this scheme, which is close enough for our purposes:
 *
 *      0.x.y   0       (0.9.8 was the last release in this series)
 *      1.0.x   1       (1.0.2 was the last release in this series)
 *      1.1.x   2       (1.1.1 was the last release in this series)
 */

/* In case someone defined both */
# if defined(OPENSSL_API_COMPAT) && defined(OPENSSL_API_LEVEL)
#  error "Disallowed to define both OPENSSL_API_COMPAT and OPENSSL_API_LEVEL"
# endif

# ifndef OPENSSL_API_COMPAT
#  define OPENSSL_API_LEVEL OPENSSL_MIN_API
# else
#  if (OPENSSL_API_COMPAT < 0x1000L) /* Major version numbers up to 16777215 */
#   define OPENSSL_API_LEVEL OPENSSL_API_COMPAT
#  elif (OPENSSL_API_COMPAT & 0xF0000000L) == 0x00000000L
#   define OPENSSL_API_LEVEL 0
#  elif (OPENSSL_API_COMPAT & 0xFFF00000L) == 0x10000000L
#   define OPENSSL_API_LEVEL 1
#  elif (OPENSSL_API_COMPAT & 0xFFF00000L) == 0x10100000L
#   define OPENSSL_API_LEVEL 2
#  else
    /* Major number 3 to 15 */
#   define OPENSSL_API_LEVEL ((OPENSSL_API_COMPAT >> 28) & 0xF)
#  endif
# endif

/*
 * Do not deprecate things to be deprecated in version 4.0 before the
 * OpenSSL version number matches.
 */
# if OPENSSL_VERSION_MAJOR < 4
#  define DEPRECATEDIN_4(f)       f;
#  define OPENSSL_API_4 0
# elif OPENSSL_API_LEVEL < 4
#  define DEPRECATEDIN_4(f)       DECLARE_DEPRECATED(f)
#  define OPENSSL_API_4 0
# else
#  define DEPRECATEDIN_4(f)
#  define OPENSSL_API_4 1
# endif

# if OPENSSL_API_LEVEL < 3
#  define DEPRECATEDIN_3(f)       DECLARE_DEPRECATED(f)
#  define OPENSSL_API_3 0
# else
#  define DEPRECATEDIN_3(f)
#  define OPENSSL_API_3 1
# endif

# if OPENSSL_API_LEVEL < 2
#  define DEPRECATEDIN_1_1_0(f)   DECLARE_DEPRECATED(f)
#  define OPENSSL_API_1_1_0 0
# else
#  define DEPRECATEDIN_1_1_0(f)
#  define OPENSSL_API_1_1_0 1
# endif

# if OPENSSL_API_LEVEL < 1
#  define DEPRECATEDIN_1_0_0(f)   DECLARE_DEPRECATED(f)
#  define OPENSSL_API_1_0_0 0
# else
#  define DEPRECATEDIN_1_0_0(f)
#  define OPENSSL_API_1_0_0 1
# endif

# if OPENSSL_API_LEVEL < 0
#  define DEPRECATEDIN_0_9_8(f)   DECLARE_DEPRECATED(f)
#  define OPENSSL_API_0_9_8 0
# else
#  define DEPRECATEDIN_0_9_8(f)
#  define OPENSSL_API_0_9_8 1
# endif

# ifndef OPENSSL_FILE
#  ifdef OPENSSL_NO_FILENAMES
#   define OPENSSL_FILE ""
#   define OPENSSL_LINE 0
#  else
#   define OPENSSL_FILE __FILE__
#   define OPENSSL_LINE __LINE__
#  endif
# endif

# if !OPENSSL_API_4
/* Synthesize OPENSSL_VERSION_NUMBER with the layout 0xMNN00PPSL */
#  ifdef OPENSSL_VERSION_PRE_RELEASE
#   define _OPENSSL_VERSION_PRE_RELEASE 0x0L
#  else
#   define _OPENSSL_VERSION_PRE_RELEASE 0xfL
#  endif
#  define OPENSSL_VERSION_NUMBER        \
          ( (OPENSSL_VERSION_MAJOR<<28)  \
            |(OPENSSL_VERSION_MINOR<<20) \
            |(OPENSSL_VERSION_PATCH<<4)  \
            |_OPENSSL_VERSION_PRE_RELEASE )
# endif

# ifdef  __cplusplus
}
# endif
#endif                          /* HEADER_OPENSSLV_H */
