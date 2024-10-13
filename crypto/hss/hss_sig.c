/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "internal/common.h"
#include "crypto/hss_sig.h"

HSS_SIG *ossl_hss_sig_new(void)
{
    HSS_SIG *ret = NULL;

    ret = OPENSSL_zalloc(sizeof(HSS_SIG));
    if (ret != NULL) {
        ret->lmskeys = sk_LMS_KEY_new_null();
        ret->lmssigs = sk_LMS_SIG_new_null();
        if (ret->lmskeys == NULL || ret->lmssigs == NULL) {
            sk_LMS_SIG_free(ret->lmssigs);
            sk_LMS_KEY_free(ret->lmskeys);
        }
    }
    return ret;
}

/*
 * @brief Destroys the list of LMS signatures, and LMS keys.
 */
void ossl_hss_sig_free(HSS_SIG *hss_sig)
{
    sk_LMS_SIG_pop_free(hss_sig->lmssigs, ossl_lms_sig_free);
    sk_LMS_KEY_pop_free(hss_sig->lmskeys, ossl_lms_key_free);
    OPENSSL_free(hss_sig);
}
