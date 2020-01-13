/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/evp.h>
#include <opentls/objects.h>
#include <opentls/x509.h>
#include <opentls/pem.h>

int PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type)
{
    return EVP_DigestInit_ex(ctx, type, NULL);
}

int PEM_SignUpdate(EVP_MD_CTX *ctx,
                   const unsigned char *data, unsigned int count)
{
    return EVP_DigestUpdate(ctx, data, count);
}

int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey)
{
    unsigned char *m;
    int i, ret = 0;
    unsigned int m_len;

    m = OPENtls_malloc(EVP_PKEY_size(pkey));
    if (m == NULL) {
        PEMerr(PEM_F_PEM_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_SignFinal(ctx, m, &m_len, pkey) <= 0)
        goto err;

    i = EVP_EncodeBlock(sigret, m, m_len);
    *siglen = i;
    ret = 1;
 err:
    /* ctx has been zeroed by EVP_SignFinal() */
    OPENtls_free(m);
    return ret;
}
