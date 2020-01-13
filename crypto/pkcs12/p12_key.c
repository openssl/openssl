/*
 * Copyright 1999-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/pkcs12.h>
#include <opentls/bn.h>
#include <opentls/trace.h>

/* PKCS12 compatible key/IV generation */
#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

int PKCS12_key_gen_asc(const char *pass, int patlsen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type)
{
    int ret;
    unsigned char *unipass;
    int uniplen;

    if (pass == NULL) {
        unipass = NULL;
        uniplen = 0;
    } else if (!OPENtls_asc2uni(pass, patlsen, &unipass, &uniplen)) {
        PKCS12err(PKCS12_F_PKCS12_KEY_GEN_ASC, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = PKCS12_key_gen_uni(unipass, uniplen, salt, saltlen,
                             id, iter, n, out, md_type);
    if (ret <= 0)
        return 0;
    OPENtls_clear_free(unipass, uniplen);
    return ret;
}

int PKCS12_key_gen_utf8(const char *pass, int patlsen, unsigned char *salt,
                        int saltlen, int id, int iter, int n,
                        unsigned char *out, const EVP_MD *md_type)
{
    int ret;
    unsigned char *unipass;
    int uniplen;

    if (pass == NULL) {
        unipass = NULL;
        uniplen = 0;
    } else if (!OPENtls_utf82uni(pass, patlsen, &unipass, &uniplen)) {
        PKCS12err(PKCS12_F_PKCS12_KEY_GEN_UTF8, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = PKCS12_key_gen_uni(unipass, uniplen, salt, saltlen,
                             id, iter, n, out, md_type);
    if (ret <= 0)
        return 0;
    OPENtls_clear_free(unipass, uniplen);
    return ret;
}

int PKCS12_key_gen_uni(unsigned char *pass, int patlsen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type)
{
    unsigned char *B = NULL, *D = NULL, *I = NULL, *p = NULL, *Ai = NULL;
    int Slen, Plen, Ilen;
    int i, j, u, v;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *tmpout = out;
    int tmpn = n;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;

    Otls_TRACE_BEGIN(PKCS12_KEYGEN) {
        BIO_printf(trc_out, "PKCS12_key_gen_uni(): ID %d, ITER %d\n", id, iter);
        BIO_printf(trc_out, "Password (length %d):\n", patlsen);
        BIO_hex_string(trc_out, 0, patlsen, pass, patlsen);
        BIO_printf(trc_out, "\n");
        BIO_printf(trc_out, "Salt (length %d):\n", saltlen);
        BIO_hex_string(trc_out, 0, saltlen, salt, saltlen);
        BIO_printf(trc_out, "\n");
    } Otls_TRACE_END(PKCS12_KEYGEN);
    v = EVP_MD_block_size(md_type);
    u = EVP_MD_size(md_type);
    if (u < 0 || v <= 0)
        goto err;
    D = OPENtls_malloc(v);
    Ai = OPENtls_malloc(u);
    B = OPENtls_malloc(v + 1);
    Slen = v * ((saltlen + v - 1) / v);
    if (patlsen)
        Plen = v * ((patlsen + v - 1) / v);
    else
        Plen = 0;
    Ilen = Slen + Plen;
    I = OPENtls_malloc(Ilen);
    if (D == NULL || Ai == NULL || B == NULL || I == NULL)
        goto err;
    for (i = 0; i < v; i++)
        D[i] = id;
    p = I;
    for (i = 0; i < Slen; i++)
        *p++ = salt[i % saltlen];
    for (i = 0; i < Plen; i++)
        *p++ = pass[i % patlsen];
    for (;;) {
        if (!EVP_DigestInit_ex(ctx, md_type, NULL)
            || !EVP_DigestUpdate(ctx, D, v)
            || !EVP_DigestUpdate(ctx, I, Ilen)
            || !EVP_DigestFinal_ex(ctx, Ai, NULL))
            goto err;
        for (j = 1; j < iter; j++) {
            if (!EVP_DigestInit_ex(ctx, md_type, NULL)
                || !EVP_DigestUpdate(ctx, Ai, u)
                || !EVP_DigestFinal_ex(ctx, Ai, NULL))
                goto err;
        }
        memcpy(out, Ai, min(n, u));
        if (u >= n) {
            Otls_TRACE_BEGIN(PKCS12_KEYGEN) {
                BIO_printf(trc_out, "Output KEY (length %d)\n", tmpn);
                BIO_hex_string(trc_out, 0, tmpn, tmpout, tmpn);
                BIO_printf(trc_out, "\n");
            } Otls_TRACE_END(PKCS12_KEYGEN);
            ret = 1;
            goto end;
        }
        n -= u;
        out += u;
        for (j = 0; j < v; j++)
            B[j] = Ai[j % u];
        for (j = 0; j < Ilen; j += v) {
            int k;
            unsigned char *Ij = I + j;
            uint16_t c = 1;

            /* Work out Ij = Ij + B + 1 */
            for (k = v - 1; k >= 0; k--) {
                c += Ij[k] + B[k];
                Ij[k] = (unsigned char)c;
                c >>= 8;
            }
        }
    }

 err:
    PKCS12err(PKCS12_F_PKCS12_KEY_GEN_UNI, ERR_R_MALLOC_FAILURE);

 end:
    OPENtls_free(Ai);
    OPENtls_free(B);
    OPENtls_free(D);
    OPENtls_free(I);
    EVP_MD_CTX_free(ctx);
    return ret;
}
