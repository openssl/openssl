/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/opentlsconf.h>
#include <opentls/opentlsv.h>

#ifndef OPENtls_MACROS_H
# define OPENtls_MACROS_H

/* Helper macros for CPP string composition */
# define OPENtls_MSTR_HELPER(x) #x
# define OPENtls_MSTR(x) OPENtls_MSTR_HELPER(x)

/*
 * Sometimes OPENStls_NO_xxx ends up with an empty file and some compilers
 * don't like that.  This will hopefully silence them.
 */
# define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

/*
 * Generic deprecation macro
  *
  * If OPENtls_SUPPRESS_DEPRECATED is defined, then DECLARE_DEPRECATED
  * becomes a no-op
 */
# ifndef DECLARE_DEPRECATED
#  define DECLARE_DEPRECATED(f)   f;
#  ifndef OPENtls_SUPPRESS_DEPRECATED
#   ifdef __GNUC__
#    if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)
#     undef DECLARE_DEPRECATED
#     define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#    endif
#   elif defined(__SUNPRO_C)
#    if (__SUNPRO_C >= 0x5130)
#     undef DECLARE_DEPRECATED
#     define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#    endif
#   endif
#  endif
# endif

/*
 * Applications should use -DOPENtls_API_COMPAT=<version> to suppress the
 * declarations of functions deprecated in or before <version>.  If this is
 * undefined, the value of the macro OPENtls_CONFIGURED_API (defined in
 * <opentls/opentlsconf.h>) is the default.
 *
 * For any version number up until version 1.1.x, <version> is expected to be
 * the calculated version number 0xMNNFFPPSL.
 * For version numbers 3.0 and on, <version> is expected to be a computation
 * of the major and minor numbers in decimal using this formula:
 *
 *     MAJOR * 10000 + MINOR * 100
 *
 * So version 3.0 becomes 30000, version 3.2 becomes 30200, etc.
 */

/*
 * We use the OPENtls_API_COMPAT value to define API level macros.  These
 * macros are used to enable or disable features at that API version boundary.
 */

# ifdef OPENtls_API_LEVEL
#  error "OPENtls_API_LEVEL must not be defined by application"
# endif

/*
 * We figure out what API level was intended by simple numeric comparison.
 * The lowest old style number we recognise is 0x00908000L, so we take some
 * safety margin and assume that anything below 0x00900000L is a new style
 * number.  This allows new versions up to and including v943.71.83.
 */
# ifdef OPENtls_API_COMPAT
#  if OPENtls_API_COMPAT < 0x900000L
#   define OPENtls_API_LEVEL (OPENtls_API_COMPAT)
#  else
#   define OPENtls_API_LEVEL                            \
           (((OPENtls_API_COMPAT >> 28) & 0xF) * 10000  \
            + ((OPENtls_API_COMPAT >> 20) & 0xFF) * 100 \
            + ((OPENtls_API_COMPAT >> 12) & 0xFF))
#  endif
# endif

/*
 * If OPENtls_API_COMPAT wasn't given, we use default numbers to set
 * the API compatibility level.
 */
# ifndef OPENtls_API_LEVEL
#  if OPENtls_CONFIGURED_API > 0
#   define OPENtls_API_LEVEL (OPENtls_CONFIGURED_API)
#  else
#   define OPENtls_API_LEVEL \
           (OPENtls_VERSION_MAJOR * 10000 + OPENtls_VERSION_MINOR * 100)
#  endif
# endif

# if OPENtls_API_LEVEL > OPENtls_CONFIGURED_API
#  error "The requested API level higher than the configured API compatibility level"
# endif

/*
 * Check of sane values.
 */
/* Can't go higher than the current version. */
# if OPENtls_API_LEVEL > (OPENtls_VERSION_MAJOR * 10000 + OPENtls_VERSION_MINOR * 100)
#  error "OPENtls_API_COMPAT expresses an impossible API compatibility level"
# endif
/* Opentls will have no version 2.y.z */
# if OPENtls_API_LEVEL < 30000 && OPENtls_API_LEVEL >= 20000
#  error "OPENtls_API_COMPAT expresses an impossible API compatibility level"
# endif
/* Below 0.9.8 is unacceptably low */
# if OPENtls_API_LEVEL < 908
#  error "OPENtls_API_COMPAT expresses an impossible API compatibility level"
# endif

/*
 * Define macros for deprecation purposes.  We always define the macros
 * DEPERECATEDIN_{major}_{minor}() for all Opentls versions we care for,
 * and OPENtls_NO_DEPRECATED_{major}_{minor} to be used to check if
 * removal of deprecated functions applies on that particular version.
 */

# undef OPENtls_NO_DEPRECATED_3_0
# undef OPENtls_NO_DEPRECATED_1_1_1
# undef OPENtls_NO_DEPRECATED_1_1_0
# undef OPENtls_NO_DEPRECATED_1_0_2
# undef OPENtls_NO_DEPRECATED_1_0_1
# undef OPENtls_NO_DEPRECATED_1_0_0
# undef OPENtls_NO_DEPRECATED_0_9_8

# if OPENtls_API_LEVEL >= 30000
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_3_0(f)       DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_3_0(f)
#   define OPENtls_NO_DEPRECATED_3_0
#  endif
# else
#  define DEPRECATEDIN_3_0(f)        f;
# endif
# if OPENtls_API_LEVEL >= 10101
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_1_1_1(f)     DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_1_1_1(f)
#   define OPENtls_NO_DEPRECATED_1_1_1
#  endif
# else
#  define DEPRECATEDIN_1_1_1(f)      f;
# endif
# if OPENtls_API_LEVEL >= 10100
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_1_1_0(f)     DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_1_1_0(f)
#   define OPENtls_NO_DEPRECATED_1_1_0
#  endif
# else
#  define DEPRECATEDIN_1_1_0(f)      f;
# endif
# if OPENtls_API_LEVEL >= 10002
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_1_0_2(f)     DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_1_0_2(f)
#   define OPENtls_NO_DEPRECATED_1_0_2
#  endif
# else
#  define DEPRECATEDIN_1_0_2(f)      f;
# endif
# if OPENtls_API_LEVEL >= 10001
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_1_0_1(f)     DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_1_0_1(f)
#   define OPENtls_NO_DEPRECATED_1_0_1
#  endif
# else
#  define DEPRECATEDIN_1_0_1(f)      f;
# endif
# if OPENtls_API_LEVEL >= 10000
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_1_0_0(f)     DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_1_0_0(f)
#   define OPENtls_NO_DEPRECATED_1_0_0
#  endif
# else
#  define DEPRECATEDIN_1_0_0(f)      f;
# endif
# if OPENtls_API_LEVEL >= 908
#  ifndef OPENtls_NO_DEPRECATED
#   define DEPRECATEDIN_0_9_8(f)     DECLARE_DEPRECATED(f)
#  else
#   define DEPRECATEDIN_0_9_8(f)
#   define OPENtls_NO_DEPRECATED_0_9_8
#  endif
# else
#  define DEPRECATEDIN_0_9_8(f)      f;
# endif

/*
 * Make our own variants of __FILE__ and __LINE__, depending on configuration
 */

# ifndef OPENtls_FILE
#  ifdef OPENtls_NO_FILENAMES
#   define OPENtls_FILE ""
#   define OPENtls_LINE 0
#  else
#   define OPENtls_FILE __FILE__
#   define OPENtls_LINE __LINE__
#  endif
# endif

/*
 * __func__ was standardized in C99, so for any compiler that claims
 * to implement that language level or newer, we assume we can safely
 * use that symbol.
 *
 * GNU C also provides __FUNCTION__ since version 2, which predates
 * C99.  We can, however, only use this if __STDC_VERSION__ exists,
 * as it's otherwise not allowed according to ISO C standards (C90).
 * (compiling with GNU C's -pedantic tells us so)
 *
 * If none of the above applies, we check if the compiler is MSVC,
 * and use __FUNCTION__ if that's the case.
 */
# ifndef OPENtls_FUNC
#  if defined(__STDC_VERSION__)
#   if __STDC_VERSION__ >= 199901L
#    define OPENtls_FUNC __func__
#   elif defined(__GNUC__) && __GNUC__ >= 2
#    define OPENtls_FUNC __FUNCTION__
#   endif
#  elif defined(_MSC_VER)
#    define OPENtls_FUNC __FUNCTION__
#  endif
/*
 * If all these possibilities are exhausted, we give up and use a
 * static string.
 */
#  ifndef OPENtls_FUNC
#   define OPENtls_FUNC "(unknown function)"
#  endif
# endif

#endif  /* OPENtls_MACROS_H */
