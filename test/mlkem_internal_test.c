/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_STDIO
# include <stdio.h>
#endif

#include <crypto/mlkem.h>

#include <string.h>
#include "testutil.h"
#include "testutil/output.h"

int main(void)
{
    uint8_t out_encoded_public_key[OSSL_MLKEM768_PUBLIC_KEY_BYTES];
    uint8_t out_ciphertext[OSSL_MLKEM768_CIPHERTEXT_BYTES];
    uint8_t out_shared_secret[OSSL_MLKEM768_SHARED_SECRET_BYTES];
    uint8_t out_shared_secret2[OSSL_MLKEM768_SHARED_SECRET_BYTES];
    ossl_mlkem768_private_key private_key;
    ossl_mlkem768_public_key public_key;
    ossl_mlkem768_public_key recreated_public_key;
    uint8_t *p1, *p2;
    ossl_mlkem_ctx *mlkem_ctx = ossl_mlkem_newctx(NULL, NULL);
    int ret = 1;

    /* enable TEST_* API */
    test_open_streams();

    /* first, generate a key pair */
    if (!ossl_mlkem768_generate_key(out_encoded_public_key, NULL,
                                    &private_key, mlkem_ctx)) {
        ret = -1;
        goto end;
    }
    /* public key component to be created from private key */
    if (!ossl_mlkem768_public_from_private(&public_key, &private_key)) {
        ret = -2;
        goto end;
    }
    /* try to re-create public key structure from encoded public key */
    if (!ossl_mlkem768_recreate_public_key(out_encoded_public_key,
                                           &recreated_public_key, mlkem_ctx)) {
        ret = -3;
        goto end;
    }
    /* validate identity of both public key structures */
    p1 = (uint8_t *)&public_key;
    p2 = (uint8_t *)&recreated_public_key;
    if (!TEST_int_eq(memcmp(p1, p2, sizeof(public_key)), 0)) {
        ret = -4;
        goto end;
    }
    /* encaps - decaps test: validate shared secret identity */
    if (!ossl_mlkem768_encap(out_ciphertext, out_shared_secret,
                             &recreated_public_key, mlkem_ctx)) {
        ret = -5;
        goto end;
    }
    if (!ossl_mlkem768_decap(out_shared_secret2, out_ciphertext,
                             OSSL_MLKEM768_CIPHERTEXT_BYTES, &private_key, mlkem_ctx)) {
        ret = -6;
        goto end;
    }
    if (!TEST_int_eq(memcmp(out_shared_secret, out_shared_secret2,
                            OSSL_MLKEM768_SHARED_SECRET_BYTES), 0)) {
        ret = -7;
        goto end;
    }
    /* so far so good, now a quick negative test by breaking the ciphertext */
    out_ciphertext[0]++;
    if (!ossl_mlkem768_decap(out_shared_secret2, out_ciphertext,
                             OSSL_MLKEM768_CIPHERTEXT_BYTES, &private_key, mlkem_ctx))
        goto end;
    /* If decap passed, ensure we at least have a mismatch */
    if (!TEST_int_ne(memcmp(out_shared_secret, out_shared_secret2,
                            OSSL_MLKEM768_SHARED_SECRET_BYTES), 0))
        ret = -8;

end:
    ossl_mlkem_ctx_free(mlkem_ctx);
    return ret;
}
