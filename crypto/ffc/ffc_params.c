/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h> /* memset */
#include "internal/ffc.h"
#ifndef FIPS_MODE
# include <openssl/asn1.h> /* ffc_params_print */
#endif

void ffc_params_init(FFC_PARAMS *params)
{
    memset(params, 0, sizeof(FFC_PARAMS));
    params->pcounter = -1;
    params->gindex = FFC_UNVERIFIABLE_GINDEX;
}

void ffc_params_cleanup(FFC_PARAMS *params)
{
    BN_free(params->p);
    BN_free(params->q);
    BN_free(params->g);
    BN_free(params->j);
    OPENSSL_free(params->seed);
    ffc_params_init(params);
}

void ffc_params_set0_pqg(FFC_PARAMS *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (p != NULL && p != d->p) {
        BN_free(d->p);
        d->p = p;
    }
    if (q != NULL && q != d->q) {
        BN_free(d->q);
        d->q = q;
    }
    if (g != NULL && g != d->g) {
        BN_free(d->g);
        d->g = g;
    }
}

void ffc_params_get0_pqg(const FFC_PARAMS *d, const BIGNUM **p,
                         const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}


/* j is the 'cofactor' that is optionally output for ASN1. */
void ffc_params_set0_j(FFC_PARAMS *d, BIGNUM *j)
{
    BN_free(d->j);
    d->j = NULL;
    if (j != NULL)
        d->j = j;
}

int ffc_params_set_validate_params(FFC_PARAMS *params,
                                   const unsigned char *seed, size_t seedlen,
                                   int counter)
{
    if (params == NULL)
        return 0;

    if (params->seed != NULL)
        OPENSSL_free(params->seed);

    if (seed != NULL && seedlen > 0) {
        params->seed = OPENSSL_memdup(seed, seedlen);
        if (params->seed == NULL)
            return 0;
        params->seedlen = seedlen;
    } else {
        params->seed = NULL;
        params->seedlen = 0;
    }
    params->pcounter = counter;
    return 1;
}

void ffc_params_get_validate_params(const FFC_PARAMS *params,
                                    unsigned char **seed, size_t *seedlen,
                                    int *pcounter)
{
    if (seed != NULL)
        *seed = params->seed;
    if (seedlen != NULL)
        *seedlen = params->seedlen;
    if (pcounter != NULL)
        *pcounter = params->pcounter;
}

static int ffc_bn_cpy(BIGNUM **dst, const BIGNUM *src)
{
    BIGNUM *a;

    /*
     * If source is read only just copy the pointer, so
     * we don't have to reallocate it.
     */
    if (src == NULL)
        a = NULL;
    else if (BN_get_flags(src, BN_FLG_STATIC_DATA)
             && !BN_get_flags(src, BN_FLG_MALLOCED))
        a = (BIGNUM *)src;
    else if ((a = BN_dup(src)) == NULL)
        return 0;
    BN_clear_free(*dst);
    *dst = a;
    return 1;
}

int ffc_params_copy(FFC_PARAMS *dst, const FFC_PARAMS *src)
{
    if (!ffc_bn_cpy(&dst->p, src->p)
        || !ffc_bn_cpy(&dst->g, src->g)
        || !ffc_bn_cpy(&dst->q, src->q)
        || !ffc_bn_cpy(&dst->j, src->j))
        return 0;

    OPENSSL_free(dst->seed);
    dst->seedlen = src->seedlen;
    if (src->seed != NULL) {
        dst->seed = OPENSSL_memdup(src->seed, src->seedlen);
        if  (dst->seed == NULL)
            return 0;
    } else {
        dst->seed = NULL;
    }
    dst->pcounter = src->pcounter;
    return 1;
}

int ffc_params_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b, int ignore_q)
{
    return BN_cmp(a->p, b->p) == 0
           && BN_cmp(a->g, b->g) == 0
           && (ignore_q || BN_cmp(a->q, b->q) == 0); /* Note: q may be NULL */
}

#ifndef FIPS_MODE
int ffc_params_print(BIO *bp, const FFC_PARAMS *ffc, int indent)
{
    if (!ASN1_bn_print(bp, "prime P:", ffc->p, NULL, indent))
        goto err;
    if (!ASN1_bn_print(bp, "generator G:", ffc->g, NULL, indent))
        goto err;
    if (ffc->q != NULL
        && !ASN1_bn_print(bp, "subgroup order Q:", ffc->q, NULL, indent))
        goto err;
    if (ffc->j != NULL
        && !ASN1_bn_print(bp, "subgroup factor:", ffc->j, NULL, indent))
        goto err;
    if (ffc->seed != NULL) {
        size_t i;
        BIO_indent(bp, indent, 128);
        BIO_puts(bp, "seed:");
        for (i = 0; i < ffc->seedlen; i++) {
            if ((i % 15) == 0) {
                if (BIO_puts(bp, "\n") <= 0
                    || !BIO_indent(bp, indent + 4, 128))
                    goto err;
            }
            if (BIO_printf(bp, "%02x%s", ffc->seed[i],
                           ((i + 1) == ffc->seedlen) ? "" : ":") <= 0)
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    if (ffc->pcounter != -1) {
        BIO_indent(bp, indent, 128);
        if (BIO_printf(bp, "counter: %d\n", ffc->pcounter) <= 0)
            goto err;
    }
    return 1;
err:
    return 0;
}
#endif /* FIPS_MODE */
