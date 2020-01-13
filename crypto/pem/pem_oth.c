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
#include <opentls/buffer.h>
#include <opentls/objects.h>
#include <opentls/evp.h>
#include <opentls/x509.h>
#include <opentls/pem.h>

/* Handle 'other' PEMs: not private keys */

void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                        pem_password_cb *cb, void *u)
{
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    char *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, NULL, name, bp, cb, u))
        return NULL;
    p = data;
    ret = d2i(x, &p, len);
    if (ret == NULL)
        PEMerr(PEM_F_PEM_ASN1_READ_BIO, ERR_R_ASN1_LIB);
    OPENtls_free(data);
    return ret;
}
