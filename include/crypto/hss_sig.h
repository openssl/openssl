/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_HSS_SIG_H
# define OSSL_CRYPTO_HSS_SIG_H
# pragma once
# ifndef OPENSSL_NO_HSS
#  include "lms_sig.h"
#  include "hss.h"

/*
 * HSS requires a tree of LMS keys, as well as a list of LMS signatures.
 * This object is used to store lists of HSS related LMS keys and signatures.
 * For signature verification it is used for decoding a signature.
 */
typedef struct hss_sig {
    STACK_OF(LMS_KEY) *lmskeys;
    STACK_OF(LMS_SIG) *lmssigs;
} HSS_SIG;

DEFINE_STACK_OF(LMS_KEY)
DEFINE_STACK_OF(LMS_SIG)

HSS_SIG *ossl_hss_sig_new(void);
void ossl_hss_sig_free(HSS_SIG *sig);

static inline LMS_KEY *ossl_hss_sig_get_lmskey(const HSS_SIG *sig, int id)
{
    return sk_LMS_KEY_value(sig->lmskeys, id);
}
static inline int ossl_hss_sig_get_lmssigcount(const HSS_SIG *sig)
{
    return sk_LMS_SIG_num(sig->lmssigs);
}
static inline LMS_SIG *ossl_hss_sig_get_lmssig(const HSS_SIG *sig, int id)
{
    return sk_LMS_SIG_value(sig->lmssigs, id);
}

int ossl_hss_sig_decode(HSS_SIG *sigs, HSS_KEY *hsskey, uint32_t L,
                        const unsigned char *sig, size_t siglen);
int ossl_hss_sig_verify(const HSS_SIG *hss_sig, const HSS_KEY *hsskey,
                        const EVP_MD *md,
                        const unsigned char *msg, size_t msglen);

# endif /* OPENSSL_NO_HSS */
#endif /* OSSL_CRYPTO_HSS_SIG_H */
