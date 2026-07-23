/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include "internal/cryptlib.h"
#include "crypto/ctype.h"
#include "internal/numbers.h"
#include <openssl/bio.h>
#include <openssl/configuration.h>

int BIO_printf(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);

    ret = BIO_vprintf(bio, format, args);

    va_end(args);
    return ret;
}

#if defined(_MSC_VER) && _MSC_VER < 1900
/*
 * _MSC_VER described here:
 * https://learn.microsoft.com/en-us/cpp/overview/compiler-versions?view=msvc-170
 *
 * Beginning with the UCRT in Visual Studio 2015 and Windows 10, snprintf is no
 * longer identical to _snprintf. The snprintf behavior is now C99 standard
 * conformant. The difference is that if you run out of buffer, snprintf
 * null-terminates the end of the buffer and returns the number of characters
 * that would have been required whereas _snprintf doesn't null-terminate the
 * buffer and returns -1. Also, snprintf() includes one more character in the
 * output because it doesn't null-terminate the buffer.
 * [ https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-snprintf-snprintf-l-snwprintf-snwprintf-l?view=msvc-170#remarks
 *
 * for older MSVC (older than 2015) we can use _vscprintf() and _vsnprintf()
 * as suggested here:
 * https://stackoverflow.com/questions/2915672/snprintf-and-visual-studio-2010
 *
 */
static int msvc_translate_printf_format(const char *format, const char **out,
    char **tmp)
{
    /* Valid printf conversion specifiers, grouped by category: signed
     * integers (d i), unsigned (o u x X), floating-point (f F e E g G a A),
     * misc (c s p n) and MSVC-specific (S Z C). */
    static const char conv[] = "diouxXfFeEgGaAcspnSZC";
    const char *p = format;
    char *dst = NULL, *q = NULL;

    /*
     * The VS 2013 CRT does not understand the C99 z, t and j length
     * modifiers. Translate z and t to I (both are pointer-sized on Windows)
     * and j to I64 (intmax_t is 64 bits). Every input character expands to
     * at most three output characters (j -> I64), so 3 * length is a safe
     * bound for the buffer.
     *
     * This is done in a single pass: nothing is allocated until the first
     * modifier is seen, so formats that need no translation return the
     * original string untouched. EMIT_CHAR() appends a character to the
     * output once the buffer exists; before that it is a no-op.
     */
#define EMIT_CHAR(c)     \
    do {                 \
        if (dst != NULL) \
            *q++ = (c);  \
    } while (0)

    *out = format;
    *tmp = NULL;

    while (*p != '\0') {
        if (*p != '%') { /* literal character */
            EMIT_CHAR(*p);
            p++;
            continue;
        }
        p++; /* consume '%' */
        if (*p == '%') { /* literal "%%" */
            EMIT_CHAR('%');
            EMIT_CHAR('%');
            p++;
            continue;
        }
        EMIT_CHAR('%');
        while (*p != '\0' && strchr(conv, *p) == NULL) {
            char c = *p++;
            if (c != 'z' && c != 't' && c != 'j') { /* verbatim */
                EMIT_CHAR(c);
                continue;
            }
            if (dst == NULL) { /* first modifier: allocate + flush prefix */
                size_t len = strlen(format);
                if (len > (SIZE_MAX - 1) / 3) /* make static analysis happy */
                    return 0;
                dst = (char *)OPENSSL_malloc(3 * len + 1);
                if (dst == NULL)
                    return 0;
                q = dst;
                memcpy(q, format, (size_t)(p - 1 - format));
                q += p - 1 - format;
            }
            EMIT_CHAR('I');
            if (c == 'j') {
                EMIT_CHAR('6');
                EMIT_CHAR('4');
            }
        }
        if (*p != '\0') { /* copy the conversion specifier */
            EMIT_CHAR(*p);
            p++;
        }
    }
#undef EMIT_CHAR

    if (dst != NULL) {
        *q = '\0';
        *out = dst;
        *tmp = dst;
    }
    return 1;
}

static int msvc_bio_vprintf(BIO *bio, const char *format, va_list args)
{
    char buf[512];
    char *abuf, *fmt_alloc;
    const char *fmt;
    int ret, sz;

    if (!msvc_translate_printf_format(format, &fmt, &fmt_alloc))
        return -1;

    sz = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    if (sz == -1) {
        sz = _vscprintf(fmt, args) + 1;
        abuf = (char *)OPENSSL_malloc(sz);
        if (abuf == NULL) {
            ret = -1;
        } else {
            sz = _vsnprintf(abuf, sz, fmt, args);
            ret = BIO_write(bio, abuf, sz);
            OPENSSL_free(abuf);
        }
    } else {
        ret = BIO_write(bio, buf, sz);
    }

    OPENSSL_free(fmt_alloc);
    return ret;
}
#endif

#ifdef _MSC_VER
/*
 * This function is for unit test on windows only when built with Visual Studio
 */
int ossl_BIO_snprintf_msvc(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
#if defined(_MSC_VER) && _MSC_VER < 1900
    {
        char *fmt_alloc;
        const char *fmt;

        if (!msvc_translate_printf_format(format, &fmt, &fmt_alloc)) {
            ret = -1;
        } else {
            ret = _vsnprintf_s(buf, n, _TRUNCATE, fmt, args);
            OPENSSL_free(fmt_alloc);
        }
    }
#else
    ret = _vsnprintf_s(buf, n, _TRUNCATE, format, args);
#endif
    va_end(args);

    return ret;
}
#endif

int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    va_list cp_args;
#if !defined(_MSC_VER) || _MSC_VER >= 1900
    int sz;
#endif
    int ret = -1;

    va_copy(cp_args, args);
#if defined(_MSC_VER) && _MSC_VER < 1900
    ret = msvc_bio_vprintf(bio, format, cp_args);
#else
    char buf[512];
    char *abuf;
    /*
     * some compilers modify va_list, hence each call to v*printf()
     * should operate with its own instance of va_list. The first
     * call to vsnprintf() here uses args we got in function argument.
     * The second call is going to use cp_args we made earlier.
     */
    sz = vsnprintf(buf, sizeof(buf), format, args);
    if (sz >= 0) {
        if ((size_t)sz >= sizeof(buf)) {
            sz += 1;
            abuf = (char *)OPENSSL_malloc(sz);
            if (abuf == NULL) {
                ret = -1;
            } else {
                sz = vsnprintf(abuf, sz, format, cp_args);
                ret = BIO_write(bio, abuf, sz);
                OPENSSL_free(abuf);
            }
        } else {
            /* vsnprintf returns length not including nul-terminator */
            ret = BIO_write(bio, buf, sz);
        }
    }
#endif
    va_end(cp_args);
    return ret;
}

/*
 * For historical reasons BIO_snprintf and friends return a failure for string
 * truncation (-1) instead of the POSIX requirement of a success with the
 * number of characters that would have been written. Upon seeing -1 on
 * return, the caller must treat output buf as unsafe (as a buf with missing
 * nul terminator).
 */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vsnprintf(buf, n, format, args);
    va_end(args);

    return ret;
}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
#if defined(_MSC_VER) && _MSC_VER < 1900
    char *fmt_alloc;
    const char *fmt;
#endif
    int ret;

#if defined(_MSC_VER) && _MSC_VER < 1900
    if (!msvc_translate_printf_format(format, &fmt, &fmt_alloc))
        return -1;
    ret = _vsnprintf_s(buf, n, _TRUNCATE, fmt, args);
    OPENSSL_free(fmt_alloc);
#else
    ret = vsnprintf(buf, n, format, args);
    if ((size_t)ret >= n)
        ret = -1;
#endif
    return ret;
}
