/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/hss_sig.h"

/*
 * @brief HSS signature validation.
 *
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_hss_sig_verify(const HSS_SIG *hss_sig, const HSS_KEY *hsskey,
                        const EVP_MD *md,
                        const unsigned char *msg, size_t msglen)
{
    int ret = 0;
    LMS_KEY *next;
    LMS_KEY *pub = ossl_hss_key_get_public(hsskey);
    int i, nspk = ossl_hss_sig_get_lmssigcount(hss_sig) - 1;

    /* Verify the signed public keys */
    for (i = 0; i < nspk; ++i) {
        next = ossl_hss_sig_get_lmskey(hss_sig, i);
        if (next == NULL)
            goto err;
        if (ossl_lms_sig_verify(ossl_hss_sig_get_lmssig(hss_sig, i), pub, md,
                                next->pub.encoded, next->pub.encodedlen) != 1)
            goto err;
        pub = next;
    }
    /* Verify the message using the public key of the leaf tree */
    if (ossl_lms_sig_verify(ossl_hss_sig_get_lmssig(hss_sig, i), pub, md,
                            msg, msglen) != 1)
        goto err;
    ret = 1;
err:
    return ret;
}
