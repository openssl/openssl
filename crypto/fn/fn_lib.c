/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <limits.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "internal/common.h"
#include "internal/constant_time.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

OSSL_FN *ossl_fn_new_internal(size_t limbs, bool securely)
{
    /* Total size of the whole OSSL_FN, in bytes */
    size_t totalsize = ossl_fn_totalsize(limbs);
    if (totalsize == 0)
        return NULL;

    OSSL_FN *ret = NULL;

    if (securely)
        ret = OPENSSL_secure_zalloc(totalsize);
    else
        ret = OPENSSL_zalloc(totalsize);

    if (ret != NULL) {
        ret->dsize = (int)limbs;
        ret->is_dynamically_allocated = 1;
        ret->is_securely_allocated = securely;
    }
    return ret;
}

static void ossl_fn_free_internal(OSSL_FN *f, bool clear)
{
    if (f == NULL)
        return;

    size_t limbssize = f->dsize * sizeof(OSSL_FN_ULONG);
    size_t totalsize = limbssize + sizeof(OSSL_FN);

    if (f->is_dynamically_allocated) {
        if (f->is_securely_allocated)
            OPENSSL_secure_clear_free(f, totalsize);
        else if (clear)
            OPENSSL_clear_free(f, totalsize);
        else
            OPENSSL_free(f);
    } else if (clear) {
        OPENSSL_cleanse(f->d, limbssize);
    }
}

OSSL_FN *OSSL_FN_new_limbs(size_t size)
{
    return ossl_fn_new_internal(size, false);
}

OSSL_FN *OSSL_FN_secure_new_limbs(size_t size)
{
    return ossl_fn_new_internal(size, true);
}

OSSL_FN *OSSL_FN_new_bytes(size_t size)
{
    return OSSL_FN_new_limbs(ossl_fn_bytes_to_limbs(size));
}

OSSL_FN *OSSL_FN_secure_new_bytes(size_t size)
{
    return OSSL_FN_secure_new_limbs(ossl_fn_bytes_to_limbs(size));
}

OSSL_FN *OSSL_FN_new_bits(size_t size)
{
    return OSSL_FN_new_bytes(ossl_fn_bits_to_bytes(size));
}

OSSL_FN *OSSL_FN_secure_new_bits(size_t size)
{
    return OSSL_FN_secure_new_bytes(ossl_fn_bits_to_bytes(size));
}

void OSSL_FN_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, false);
}

void OSSL_FN_clear_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, true);
}

void OSSL_FN_clear(OSSL_FN *f)
{
    size_t limbssize = f->dsize * sizeof(OSSL_FN_ULONG);

    OPENSSL_cleanse(f->d, limbssize);
}

OSSL_FN *OSSL_FN_copy(OSSL_FN *a, const OSSL_FN *b)
{
    if (ossl_unlikely(a == b))
        return a;

    size_t al = a->dsize;
    size_t bl = b->dsize;

    if (al < bl) {
        ERR_raise_data(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL,
            "Needs to be at least %zu bytes, but is only %zu bytes",
            bl * sizeof(OSSL_FN_ULONG), al * sizeof(OSSL_FN_ULONG));
        return 0;
    }

    memcpy(a->d, b->d, bl * sizeof(OSSL_FN_ULONG));
    memset(a->d + bl, 0, (al - bl) * sizeof(OSSL_FN_ULONG));
    return a;
}

OSSL_FN *OSSL_FN_copy_truncate(OSSL_FN *a, const OSSL_FN *b)
{
    if (ossl_unlikely(a == b))
        return a;

    size_t al = a->dsize;
    size_t bl = b->dsize;

    if (ossl_unlikely(al > bl)) {
        memcpy(a->d, b->d, bl * sizeof(OSSL_FN_ULONG));
        memset(&a->d[bl], 0, sizeof(OSSL_FN_ULONG) * (al - bl));
    } else {
        memcpy(a->d, b->d, al * sizeof(OSSL_FN_ULONG));
    }

    return a;
}

OSSL_FN_ULONG OSSL_FN_lshift(OSSL_FN *a, int n)
{
    int i;
    if (n <= 0 || a == NULL)
        return 0;
    int n_limbs = n / (sizeof(OSSL_FN_ULONG) * 8);
    int n_bits = n % (sizeof(OSSL_FN_ULONG) * 8);

    if (n_limbs >= a->dsize) {
        memset(a->d, 0, a->dsize * sizeof(OSSL_FN_ULONG));
        return 0;
    }

    if (n_limbs > 0) {
        for (i = a->dsize - n_limbs - 1; i >= 0; i--)
            a->d[i + n_limbs] = a->d[i];
        memset(a->d, 0, n_limbs * sizeof(OSSL_FN_ULONG));
    }

    OSSL_FN_ULONG carry = 0, tmp;
    if (n_bits > 0)
        for (i = 0; i < a->dsize; i++) {
            tmp = a->d[i];
            a->d[i] = tmp << n_bits | carry;
            carry = tmp >> (sizeof(OSSL_FN_ULONG) * 8 - n_bits);
        }

    return carry;
}

int OSSL_FN_num_bits(const OSSL_FN *a)
{
    if (a == NULL || a->dsize == 0)
        return 0;
    int i;
    for (i = a->dsize - 1; i > 0; i--)
        if (a->d[i] != 0)
            break;
    return i * sizeof(OSSL_FN_ULONG) * 8 + BN_num_bits_word(a->d[i]);
}

int OSSL_FN_cmp(const OSSL_FN *a, const OSSL_FN *b)
{
    int check_a = (a == NULL || a->dsize == 0);
    int check_b = (b == NULL || b->dsize == 0);
    if (check_a || check_b)
        return check_b - check_a;

    int i;
    int res = 0;
    int min_dsize = a->dsize < b->dsize ? a->dsize : b->dsize;

    for (i = 0; i < min_dsize; ++i) {
        res = constant_time_select_int((int)constant_time_lt_bn(a->d[i], b->d[i]),
            -1, res);
        res = constant_time_select_int((int)constant_time_lt_bn(b->d[i], a->d[i]),
            1, res);
    }

    for (i = min_dsize; i < a->dsize; ++i)
        res = constant_time_select_int((int)constant_time_is_zero_bn(a->d[i]), res, 1);

    for (i = min_dsize; i < b->dsize; ++i)
        res = constant_time_select_int((int)constant_time_is_zero_bn(b->d[i]), res, -1);

    return res;
}

static int hex_to_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int OSSL_FN_hex2fn(OSSL_FN *r, const char *hex)
{
    size_t len, i, limb, shift;
    int v;

    if (r == NULL || hex == NULL || *hex == '-')
        return 0;

    len = strlen(hex);

    if ((size_t)r->dsize < ossl_fn_bytes_to_limbs((len + 1) / 2))
        return 0;

    memset(r->d, 0, r->dsize * sizeof(OSSL_FN_ULONG));
    for (i = len, shift = 0, limb = 0; i > 0;) {
        v = hex_to_nibble(hex[--i]);
        if (v < 0)
            return 0;

        r->d[limb] |= (OSSL_FN_ULONG)v << shift;
        shift += 4;
        if (shift == OSSL_FN_BYTES * 8) {
            shift = 0;
            limb++;
        }
    }

    return 1;
}
