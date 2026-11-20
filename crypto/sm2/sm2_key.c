/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h" /* to be able to use EC_KEY and EC_GROUP */

#include <openssl/err.h>
#include "crypto/sm2err.h"
#include "crypto/sm2.h"
#include "crypto/bn.h" /* bn_get_ossl_fsn(), bn_get_top() */
#include "crypto/fsn.h"
#include <openssl/ec.h> /* EC_KEY and EC_GROUP functions */

/*
 * SM2 key generation is implemented within ec_generate_key() in
 * crypto/ec/ec_key.c
 */

int ossl_sm2_key_private_check(const EC_KEY *eckey)
{
    int ret = 0;
    OSSL_FSN *max = NULL;
    const OSSL_FSN *priv_fsn = NULL, *order_fsn = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL, *order = NULL;

    if (eckey == NULL
        || (group = EC_KEY_get0_group(eckey)) == NULL
        || (priv_key = EC_KEY_get0_private_key(eckey)) == NULL
        || (order = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * The private key is compared as an OSSL_FSN, read through its BIGNUM's
     * view.  The bound is derived from the order and so is public, but it is
     * built as an OSSL_FSN too, since that is what it is compared against.
     */
    if ((priv_fsn = bn_get_ossl_fsn(priv_key)) == NULL
        || (order_fsn = bn_get_ossl_fsn(order)) == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        return 0;
    }

    /* range of SM2 private key is [1, n-1) */
    max = OSSL_FSN_new_limbs(bn_get_top(order));
    if (max == NULL
        || OSSL_FSN_copy_truncate(max, order_fsn) == NULL
        || !OSSL_FSN_sub_word(max, 1))
        goto end;
    /*
     * OSSL_FSN is unsigned, so a negative key has to be caught at the BIGNUM
     * boundary: its OSSL_FSN view is the magnitude, which would pass.  The
     * "< 1" of the BIGNUM version is a zero test once the sign is out of the
     * way.
     */
    if (BN_is_negative(priv_key)
        || OSSL_FSN_is_zero(priv_fsn)
        || OSSL_FSN_cmp(priv_fsn, max) >= 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY);
        goto end;
    }
    ret = 1;

end:
    OSSL_FSN_free(max);
    return ret;
}
