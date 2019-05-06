/*
 * Copyright 2003-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <limits.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"

char *CRYPTO_strdup(const char *str, const char* file, int line)
{
    char *ret;

    if (str == NULL)
        return NULL;
    ret = CRYPTO_malloc(strlen(str) + 1, file, line);
    if (ret != NULL)
        strcpy(ret, str);
    return ret;
}

char *CRYPTO_strndup(const char *str, size_t s, const char* file, int line)
{
    size_t maxlen;
    char *ret;

    if (str == NULL)
        return NULL;

    maxlen = OPENSSL_strnlen(str, s);

    ret = CRYPTO_malloc(maxlen + 1, file, line);
    if (ret) {
        memcpy(ret, str, maxlen);
        ret[maxlen] = '\0';
    }
    return ret;
}

void *CRYPTO_memdup(const void *data, size_t siz, const char* file, int line)
{
    void *ret;

    if (data == NULL || siz >= INT_MAX)
        return NULL;

    ret = CRYPTO_malloc(siz, file, line);
    if (ret == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_MEMDUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return memcpy(ret, data, siz);
}

/*
 * Give a string of hex digits convert to a buffer
 */
unsigned char *OPENSSL_hexstr2buf(const char *str, long *len)
{
    unsigned char *hexbuf, *q;
    unsigned char ch, cl;
    int chi, cli;
    const unsigned char *p;
    size_t s;

    s = strlen(str);
    if ((hexbuf = OPENSSL_malloc(s >> 1)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (p = (const unsigned char *)str, q = hexbuf; *p; ) {
        ch = *p++;
        if (ch == ':')
            continue;
        cl = *p++;
        if (!cl) {
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF,
                      CRYPTO_R_ODD_NUMBER_OF_DIGITS);
            OPENSSL_free(hexbuf);
            return NULL;
        }
        cli = OPENSSL_hexchar2int(cl);
        chi = OPENSSL_hexchar2int(ch);
        if (cli < 0 || chi < 0) {
            OPENSSL_free(hexbuf);
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ILLEGAL_HEX_DIGIT);
            return NULL;
        }
        *q++ = (unsigned char)((chi << 4) | cli);
    }

    if (len)
        *len = q - hexbuf;
    return hexbuf;
}

/*
 * Given a buffer of length 'len' return a OPENSSL_malloc'ed string with its
 * hex representation @@@ (Contents of buffer are always kept in ASCII, also
 * on EBCDIC machines)
 */
char *OPENSSL_buf2hexstr(const unsigned char *buffer, long len)
{
    static const char hexdig[] = "0123456789ABCDEF";
    char *tmp, *q;
    const unsigned char *p;
    int i;

    if (len == 0)
        return OPENSSL_zalloc(1);

    if ((tmp = OPENSSL_malloc(len * 3)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_BUF2HEXSTR, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
        *q++ = ':';
    }
    q[-1] = 0;
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif

    return tmp;
}
