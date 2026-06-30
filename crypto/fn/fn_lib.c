/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/common.h"
#include "crypto/fnerr.h"
#include "fn_local.h"
#include "internal/constant_time.h"

static OSSL_FN *ossl_fn_new_internal(size_t limbs, bool securely)
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

static size_t ossl_fn_num_bits_word(OSSL_FN_ULONG l)
{
    OSSL_FN_ULONG x, mask;
    size_t bits = (size_t)constant_time_select_int(
        (unsigned int)constant_time_is_zero_bn(l), 0, 1);

#if OSSL_FN_BITS > 32
    x = l >> 32;
    mask = ~constant_time_is_zero_bn(x);
    bits += 32 & (size_t)mask;
    l ^= (x ^ l) & mask;
#endif

    x = l >> 16;
    mask = ~constant_time_is_zero_bn(x);
    bits += 16 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 8;
    mask = ~constant_time_is_zero_bn(x);
    bits += 8 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 4;
    mask = ~constant_time_is_zero_bn(x);
    bits += 4 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 2;
    mask = ~constant_time_is_zero_bn(x);
    bits += 2 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 1;
    mask = ~constant_time_is_zero_bn(x);
    bits += 1 & (size_t)mask;

    return bits;
}

size_t OSSL_FN_num_bits(const OSSL_FN *a)
{
    size_t i;
    size_t dsize = (size_t)a->dsize;
    size_t ret = 0;

    for (i = 0; i < dsize; i++) {
        size_t limb_bits = ossl_fn_num_bits_word(a->d[i]);
        size_t bits = i * OSSL_FN_BITS + limb_bits;
        size_t mask = (size_t)~constant_time_is_zero_bn(a->d[i]);

        ret = constant_time_select_s(mask, bits, ret);
    }

    return ret;
}

int OSSL_FN_cmp(const OSSL_FN *a, const OSSL_FN *b)
{
    size_t i;
    size_t asize = (size_t)a->dsize;
    size_t bsize = (size_t)b->dsize;
    size_t max = asize > bsize ? asize : bsize;
    int res = 0;

    for (i = 0; i < max; i++) {
        OSSL_FN_ULONG aw = i < asize ? a->d[i] : 0;
        OSSL_FN_ULONG bw = i < bsize ? b->d[i] : 0;

        res = constant_time_select_int(
            (unsigned int)constant_time_lt_bn(aw, bw), -1, res);
        res = constant_time_select_int(
            (unsigned int)constant_time_lt_bn(bw, aw), 1, res);
    }

    return res;
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
