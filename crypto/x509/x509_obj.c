/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include "crypto/x509.h"
#include "crypto/ctype.h"

#if !defined(TRUE) && !defined(FALSE)
# define TRUE  1
# define FALSE (!TRUE)
#endif
#ifdef UNINITIALIZED
# undef UNINITIALIZED
#endif
#define UNINITIALIZED (-1)

#ifdef DEL
# undef DEL
#endif
#ifndef CHARSET_EBCDIC
# define DEL 127
#else
# define DEL 7
#endif

/*
 * Limit to ensure we don't overflow: much greater than
 * anything encountered in practice.
 */

#define NAME_ONELINE_MAX    (1024 * 1024)

/*
 * X509_NAME_online_with_bool() is the foundation of both X509_NAME_oneline()
 * and X509_NAME_oneline_for_locale(). It prints a version of "a" to "buf".
 * If "is_hex_escaping_non_ASCII" is TRUE, then non-ASCII UTF-8 characters
 * will be hex-escaped, and "buf" will be ASCII; if it's FALSE, then
 * such characters will remain UTF-8 if the X.509 NAME entry value type
 * is UTF8String. If "buf" is NULL, then a buffer is dynamically allocated
 * and returned, and "len" is ignored. Otherwise, at most "len" bytes will
 * be written, including the ending '\0', and "buf" is returned.
 */

static char *X509_NAME_oneline_with_bool(const X509_NAME *a, char *buf,
                                         int len,
                                         int is_hex_escaping_non_ASCII)
{
    const X509_NAME_ENTRY *ne;
    int i;
    int n, lold, l, l1, l2, num, j, type;
    int prev_set = -1;
    const char *s;
    char *p;
    unsigned char *q;
    BUF_MEM *b = NULL;
    int gs_doit[4];
    char tmp_buf[80];
#ifdef CHARSET_EBCDIC
    unsigned char ebcdic_buf[1024];
#endif

    if (buf == NULL) {
        if ((b = BUF_MEM_new()) == NULL)
            goto buferr;
        if (!BUF_MEM_grow(b, 200))
            goto buferr;
        b->data[0] = '\0';
        len = 200;
    } else if (len == 0) {
        return NULL;
    }
    if (a == NULL) {
        if (b) {
            buf = b->data;
            OPENSSL_free(b);
        }
        strncpy(buf, "NO X509_NAME", len);
        buf[len - 1] = '\0';
        return buf;
    }

    if (is_hex_escaping_non_ASCII != TRUE &&
        is_hex_escaping_non_ASCII != FALSE)
        is_hex_escaping_non_ASCII = TRUE;

    len--;                      /* space for '\0' */
    l = 0;
    for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
        int is_hex_escaping = is_hex_escaping_non_ASCII;

        ne = sk_X509_NAME_ENTRY_value(a->entries, i);
        n = OBJ_obj2nid(ne->object);
        if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
            i2t_ASN1_OBJECT(tmp_buf, sizeof(tmp_buf), ne->object);
            s = tmp_buf;
        }
        l1 = strlen(s);

        type = ne->value->type;

        if (!is_hex_escaping && type != V_ASN1_UTF8STRING)
            is_hex_escaping = TRUE;

        num = ne->value->length;
        if (num > NAME_ONELINE_MAX) {
            ERR_raise(ERR_LIB_X509, X509_R_NAME_TOO_LONG);
            goto end;
        }
        q = ne->value->data;
#ifdef CHARSET_EBCDIC
        if (type == V_ASN1_GENERALSTRING ||
            type == V_ASN1_VISIBLESTRING ||
            type == V_ASN1_PRINTABLESTRING ||
            type == V_ASN1_TELETEXSTRING ||
            type == V_ASN1_IA5STRING) {
            if (num > (int)sizeof(ebcdic_buf))
                num = sizeof(ebcdic_buf);
            ascii2ebcdic(ebcdic_buf, q, num);
            q = ebcdic_buf;
        }
#endif

        if ((type == V_ASN1_GENERALSTRING) && ((num % 4) == 0)) {
            gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 0;
            for (j = 0; j < num; j++)
                if (q[j] != 0)
                    gs_doit[j & 3] = 1;

            if (gs_doit[0] | gs_doit[1] | gs_doit[2])
                gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 1;
            else {
                gs_doit[0] = gs_doit[1] = gs_doit[2] = 0;
                gs_doit[3] = 1;
            }
        } else
            gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 1;

        for (l2 = j = 0; j < num; j++) {
            if (!gs_doit[j & 3])
                continue;
            l2++;
            if (q[j] == '/' || q[j] == '+')
                l2++; /* char needs to be escaped */
            else if (ossl_toascii(q[j]) < ossl_toascii(' ') ||
                     ossl_toascii(q[j]) == ossl_toascii(DEL) ||
                     (is_hex_escaping &&
                      ossl_toascii(q[j]) > ossl_toascii('~')))
                l2 += 3;
        }

        lold = l;
        l += 1 + l1 + 1 + l2;
        if (l > NAME_ONELINE_MAX) {
            ERR_raise(ERR_LIB_X509, X509_R_NAME_TOO_LONG);
            goto end;
        }
        if (b != NULL) {
            if (!BUF_MEM_grow(b, l + 1))
                goto buferr;
            p = &(b->data[lold]);
        } else if (l > len) {
            break;
        } else
            p = &(buf[lold]);
        *(p++) = (prev_set == ne->set) ? '+' : '/';
        memcpy(p, s, (size_t)l1);
        p += l1;
        *(p++) = '=';

#ifndef CHARSET_EBCDIC          /* q was assigned above already. */
        q = ne->value->data;
#endif

        for (j = 0; j < num; j++) {
            if (!gs_doit[j & 3])
                continue;
#ifndef CHARSET_EBCDIC
            n = q[j];
            if (n < ' ' || n == DEL || (is_hex_escaping && n > '~')) {
                *(p++) = '\\';
                *(p++) = 'x';
                p += ossl_to_hex(p, n);
            } else {
                if (n == '/' || n == '+')
                    *(p++) = '\\';
                *(p++) = (char)((unsigned char)n);
            }
#else
            n = os_toascii[q[j]];
            if (n < os_toascii[' '] || n == os_toascii[DEL]
                || (is_hex_escaping && n > os_toascii['~'])) {
                *(p++) = '\\';
                *(p++) = 'x';
                p += ossl_to_hex(p, n);
            } else {
                if (n == os_toascii['/'] || n == os_toascii['+'])
                    *(p++) = '\\';
                *(p++) = q[j];
            }
#endif
        }
        *p = '\0';
        prev_set = ne->set;
    }
    if (b != NULL) {
        p = b->data;
        OPENSSL_free(b);
    } else
        p = buf;
    if (i == 0)
        *p = '\0';
    return p;
 buferr:
    ERR_raise(ERR_LIB_X509, ERR_R_BUF_LIB);
 end:
    BUF_MEM_free(b);
    return NULL;
}

char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size)
{
    return X509_NAME_oneline_with_bool(a, buf, size, TRUE);
}

/*
 * If the locale of the process specifies the UTF-8 codeset,
 * then don't hex-escape non-ASCII UTF-8-encoded characters
 * via X509_NAME_oneline_for_locale().
 *
 * However, if the X.509 NAME entry value type is not UTF8String,
 * then non-ASCII UTF-8-encoded characters will always be
 * hex-escaped in X509_NAME_oneline_with_bool(), even if
 * the provided is_hex_escaping_non_ASCII value is FALSE.
 */

char *X509_NAME_oneline_for_locale(const X509_NAME *a, char *buf, int size)
{
    static int is_hex_escaping_non_ASCII = UNINITIALIZED;

    if (is_hex_escaping_non_ASCII == UNINITIALIZED) {
        static const char *environment_variable[] = {
            "LC_ALL", "LC_CTYPE", "LANG", NULL
        };
        static const char utf_8[] = ".UTF-8";
        static const size_t utf_8_len =
            sizeof utf_8 / sizeof *utf_8 - sizeof *utf_8;
        const char **this_environment_variable;

        /*
         * Check LC_ALL, LC_CTYPE, and LANG, in this order.
         * Only process the first non-NULL value found.
         */
        for (this_environment_variable = environment_variable;
             *this_environment_variable != NULL;
             ++this_environment_variable) {
            char *this_environment_value = getenv(*this_environment_variable);

            if (this_environment_value != NULL) {
                size_t length = strlen(this_environment_value);

                is_hex_escaping_non_ASCII =
                    (length <= utf_8_len
                     || strncmp(this_environment_value + length - utf_8_len,
                                utf_8, utf_8_len) != 0)
                    ? TRUE : FALSE;
                break;
            }
        }

        if (is_hex_escaping_non_ASCII == UNINITIALIZED)
            is_hex_escaping_non_ASCII = TRUE;
    }

    return X509_NAME_oneline_with_bool(a, buf, size,
                                       is_hex_escaping_non_ASCII);
}
