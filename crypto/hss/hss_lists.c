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
#include <openssl/hss.h>
#include "internal/common.h"
#include "crypto/hss.h"
#include "lms_local.h"

/*
 * @brief Creates empty lists of LMS signatures, and LMS keys.
 *
 * @returns 1 on success, or 0 otherwise
 */
int ossl_hss_lists_init(HSS_LISTS *lists)
{
    if (lists->lmskeys == NULL) {
        lists->lmskeys = sk_LMS_KEY_new_null();
        if (lists->lmskeys == NULL)
            goto err;
    } else {
        LMS_KEY *key;

        while ((key = sk_LMS_KEY_pop(lists->lmskeys)) != NULL)
            ossl_lms_key_free(key);
    }

    if (lists->lmssigs == NULL) {
        lists->lmssigs = sk_LMS_SIG_new_null();
        if (lists->lmssigs == NULL)
            goto err;
    } else {
        LMS_SIG *sig;

        while ((sig = sk_LMS_SIG_pop(lists->lmssigs)) != NULL)
            ossl_lms_sig_free(sig);
    }
    return 1;
 err:
    ossl_hss_lists_free(lists);
    return 0;
}

/*
 * @brief Destroys the list of LMS signatures, and LMS keys.
 */
void ossl_hss_lists_free(HSS_LISTS *lists)
{
    sk_LMS_SIG_pop_free(lists->lmssigs, ossl_lms_sig_free);
    sk_LMS_KEY_pop_free(lists->lmskeys, ossl_lms_key_free);
}

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
/*
 * @brief Perform a deep copy of the LMS_KEY and LMS_SIG lists.
 */
int ossl_hss_lists_copy(HSS_LISTS *dst, const HSS_LISTS *src)
{
    dst->lmskeys = sk_LMS_KEY_deep_copy(src->lmskeys,
                                        ossl_lms_key_deep_copy,
                                        ossl_lms_key_free);
    dst->lmssigs = sk_LMS_SIG_deep_copy(src->lmssigs,
                                        ossl_lms_sig_deep_copy,
                                        ossl_lms_sig_free);
    return (dst->lmskeys != NULL && dst->lmssigs != NULL);
}
#endif
