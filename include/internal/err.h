/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_ERR_H
#define OSSL_INTERNAL_ERR_H
#pragma once

#include <openssl/e_os2.h>

#define ERR_NUM_ERRORS 16

void err_free_strings_int(void);

/**
 * @brief Render a string that may be NULL for a %s conversion.
 *
 * @param str the string to render, which may be NULL
 * @returns str, or the string "<NULL>" if str is NULL
 */
static ossl_inline const char *ossl_string_or_null(const char *str)
{
    return str != NULL ? str : "<NULL>";
}

/**
 * @brief Append printf(3) formatted text to the most recent error's data.
 *
 * The text is appended to the data that error already carries, so repeated
 * calls accumulate; if it carries none, the text becomes its data.  Nothing
 * is raised when the error queue is empty, and a failure to store the text
 * is not reported.
 *
 * A NULL pointer passed for a %s conversion is undefined, not rendered as
 * "<NULL>" the way ERR_add_error_data() renders it.
 *
 * @param fmt printf(3) style format string describing the text to append
 * @see ERR_add_error_data(3)
 */
#define ossl_err__attr__(x)
#if defined(__GNUC__) && !defined(__MINGW32__) && !defined(__MINGW64__) \
    && !defined(__APPLE__)
#undef ossl_err__attr__
#define ossl_err__attr__ __attribute__
#endif
void ossl_err_add_error_fmt(const char *fmt, ...)
    ossl_err__attr__((__format__(__printf__, 1, 2)));
#undef ossl_err__attr__

#endif
