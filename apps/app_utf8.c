/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "apps.h"
#include <openssl/asn1.h>        /* For UTF8_putc */

/* Fallback to iconv */
# define IMPLEMENT_ICONV

/* Decide on more specific implementations */
#ifdef _WIN32
/* Windows has its own stuff */
# undef IMPLEMENT_ICONV
# define IMPLEMENT_WIN32
#endif

/* The check of GNU libc is a bit more complex */
/* Note that __GLIBC__ gets defined on the fly via string.h */
#ifdef __GLIBC__
# if __GLIBC__ >= 2
#  undef IMPLEMENT_ICONV
#  define IMPLEMENT_MBSTOWCS
# endif
#endif

#if defined(OPENSSL_TEST_ICONV) || defined(OPENSSL_TEST_NOCONV)
# undef IMPLEMENT_WIN32
# undef IMPLEMENT_MBSTOWCS
# undef IMPLEMENT_ICONV
#endif
#ifdef OPENSSL_TEST_ICONV
# define IMPLEMENT_ICONV
#endif

#if !defined(OPENSSL_TEST_NOCONV) && defined(OPENSSL_DEBUG_KEYGEN)
static void display_str(const char *txt, const char *str)
{
    if (txt != NULL)
        fprintf(stderr, "%s", txt);
    if (str != NULL) {
        size_t len = strlen(str);
        for (; len--; str++)
            fprintf(stderr, "%02X", *(const unsigned char *)str);
        fprintf(stderr, "\n");
    }
}
#else
# define display_str(txt, s) do {} while(0)
#endif

#if defined(IMPLEMENT_WIN32) || defined(IMPLEMENT_MBSTOWCS)
/* This can be used if we know that wchar_t contains UCS-x */
/*
 * We use our own rather than iconv for two reasons:
 * 1. We're not sure iconv is available "everywhere"
 * 2. We assume that any normalization is done by
 *    mbstowcs() and that a naïve conversion to UTF8
 *    is therefore harmless.
 */
static char *wchar_t2utf8(const wchar_t *wstr, size_t wstr_size)
{
    char *str_utf8 = NULL;
    size_t utf8_count, i, j;

    utf8_count = 0;
    for (i = 0; i < wstr_size; i++)
        utf8_count += UTF8_putc(NULL, 0, wstr[i]);

    if ((str_utf8 = OPENSSL_malloc(utf8_count + 1)) != NULL) {
        for (i = 0, j = 0; i < wstr_size; i++)
            j += UTF8_putc((unsigned char *)&str_utf8[j], utf8_count - j,
                           wstr[i]);
    }

    return str_utf8;
}
#endif

#if defined(IMPLEMENT_WIN32)

#include <windows.h>

char *to_utf8(const char *str)
{
    char *str_utf8 = NULL;
    wchar_t *wstr = NULL;
    size_t wstr_size;

    display_str("Input chars [WIN32]: ", str);

    if (GetEnvironmentVariableW(L"OPENSSL_WIN32_UTF8", NULL, 0) != 0) {
        display_str("is already UTF-8\n", NULL);
        return OPENSSL_strdup(str);
    }

    if ((wstr_size = MultiByteToWideChar(CP_ACP,
                                         MB_ERR_INVALID_CHARS | MB_PRECOMPOSED,
                                         str, -1, NULL, 0)) == 0
        || (wstr = OPENSSL_malloc(wstr_size * sizeof(*wstr))) == NULL)
        return NULL;
    MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS | MB_PRECOMPOSED,
                        str, -1, wstr, wstr_size);

    /* We know that wstr is UCS-2, we can use this */
    str_utf8 = wchar_t2utf8(wstr, wstr_size);
    OPENSSL_free(wstr);

    display_str("Output chars [WIN32]: ", str_utf8);
    return str_utf8;
}

#elif defined(IMPLEMENT_MBSTOWCS)

#include <stdlib.h>
#include <wchar.h>

char *to_utf8(const char *str)
{
    char *str_utf8 = NULL;
    wchar_t *wstr = NULL;
    size_t wstr_size;

    display_str("Input chars[mbstowcs]: ", str);

    if ((wstr_size = mbstowcs(NULL, str, 0)) == (size_t)-1
        || (wstr = OPENSSL_malloc(++wstr_size * sizeof(*wstr))) == NULL)
        return NULL;
    mbstowcs(wstr, str, wstr_size);

    /* We know that wstr is UCS-2, we can use this */
    str_utf8 = wchar_t2utf8(wstr, wstr_size);
    OPENSSL_free(wstr);

    display_str("Output chars[mbstowcs]: ", str_utf8);
    return str_utf8;
}

#elif defined(IMPLEMENT_ICONV)

/* Fall back to iconv */

#include <langinfo.h>
#include <iconv.h>

char *to_utf8(const char *str)
{
    const char *from = nl_langinfo(CODESET);
    iconv_t cd;
    char *inptr = (char *)str;
    size_t insize = strlen(str) + 1; /* Include NUL byte */
    size_t inbytesleft = insize;
    char *outbuf = NULL;
    char *outptr = NULL;
    size_t outsize = 0;
    size_t outbytesleft = 0;
    size_t iconv_res = 0;

    display_str("Input chars[iconv]: ", str);

    if ((cd = iconv_open("UTF-8", from)) == (iconv_t)-1)
        return NULL;

    while(1) {
        char *newbuf = NULL;

        if ((newbuf = OPENSSL_realloc(outbuf, outsize + 1024)) == NULL) {
            errno = E2BIG;
            iconv_res = (size_t)-1;
            break;
        }
        outbuf = newbuf;
        outsize += 1024;
        outbytesleft += 1024;
        outptr = outbuf + outsize - outbytesleft;

        if ((iconv_res = iconv(cd, &inptr, &inbytesleft,
                               &outptr, &outbytesleft)) != (size_t)-1
            || errno != E2BIG)
            break;
    }

    if (iconv_res == (size_t)-1) {
        OPENSSL_free(outbuf);
        outbuf = NULL;
    }

    iconv_close(cd);

    display_str("Output chars[iconv]: ", outbuf);
    return outbuf;
}

#else

/* Fallback that fails for everything but ASCII */

char *to_utf8(const char *str)
{
    return NULL;
}

#endif

int is_asciistr(const char *str)
{
    for(; *str != '\0'; str++)
        if ((*str & 0x80) != 0)
            return 0;
    return 1;
}
