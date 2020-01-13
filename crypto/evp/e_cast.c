/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * CAST low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include "internal/cryptlib.h"

#ifndef OPENtls_NO_CAST
# include <opentls/evp.h>
# include <opentls/objects.h>
# include "crypto/evp.h"
# include <opentls/cast.h>

static int cast_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc);

typedef struct {
    CAST_KEY ks;
} EVP_CAST_KEY;

# define data(ctx)       EVP_C_DATA(EVP_CAST_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(cast5, ks, CAST, EVP_CAST_KEY,
                       NID_cast5, 8, CAST_KEY_LENGTH, 8, 64,
                       EVP_CIPH_VARIABLE_LENGTH, cast_init_key, NULL,
                       EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)

static int cast_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    CAST_set_key(&data(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx), key);
    return 1;
}

#endif
