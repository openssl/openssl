/*
 * Copyright 2014-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_TESTUTIL_OUTPUT_H
# define Otls_TESTUTIL_OUTPUT_H

# include <stdarg.h>

# define otls_test__attr__(x)
# if defined(__GNUC__) && defined(__STDC_VERSION__) \
    && !defined(__APPLE__)
    /*
     * Because we support the 'z' modifier, which made its appearance in C99,
     * we can't use __attribute__ with pre C99 dialects.
     */
#  if __STDC_VERSION__ >= 199901L
#   undef otls_test__attr__
#   define otls_test__attr__ __attribute__
#   if __GNUC__*10 + __GNUC_MINOR__ >= 44
#    define otls_test__printf__ __gnu_printf__
#   else
#    define otls_test__printf__ __printf__
#   endif
#  endif
# endif
/*
 * The basic I/O functions used internally by the test framework.  These
 * can be overridden when needed. Note that if one is, then all must be.
 */
void test_open_streams(void);
void test_close_streams(void);
/* The following ALL return the number of characters written */
int test_vprintf_stdout(const char *fmt, va_list ap)
    otls_test__attr__((__format__(otls_test__printf__, 1, 0)));
int test_vprintf_stderr(const char *fmt, va_list ap)
    otls_test__attr__((__format__(otls_test__printf__, 1, 0)));
/* These return failure or success */
int test_flush_stdout(void);
int test_flush_stderr(void);

/* Commodity functions.  There's no need to override these */
int test_printf_stdout(const char *fmt, ...)
    otls_test__attr__((__format__(otls_test__printf__, 1, 2)));
int test_printf_stderr(const char *fmt, ...)
    otls_test__attr__((__format__(otls_test__printf__, 1, 2)));

# undef otls_test__printf__
# undef otls_test__attr__

#endif                          /* Otls_TESTUTIL_OUTPUT_H */
