/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/rsa.h"           /* rsa_get0_all_params() */
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/implementations.h" /* rsa_keymgmt_functions */
#include "serializer_local.h"

DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_rsa_new(void)
{
    return ossl_prov_get_keymgmt_new(rsa_keymgmt_functions);
}

OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_rsa_free(void)
{
    return ossl_prov_get_keymgmt_free(rsa_keymgmt_functions);
}

OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_rsa_import(void)
{
    return ossl_prov_get_keymgmt_import(rsa_keymgmt_functions);
}

int ossl_prov_print_rsa(BIO *out, RSA *rsa, int priv)
{
    const char *modulus_label;
    const char *exponent_label;
    const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
    STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();
    int ret = 0;

    if (rsa == NULL || factors == NULL || exps == NULL || coeffs == NULL)
        goto err;

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    rsa_get0_all_params(rsa, factors, exps, coeffs);

    if (priv && rsa_d != NULL) {
        if (ossl_prov_bio_printf(out, "Private-Key: (%d bit, %d primes)\n",
                                 BN_num_bits(rsa_n),
                                 sk_BIGNUM_const_num(factors)) <= 0)
            goto err;
        modulus_label = "modulus:";
        exponent_label = "publicExponent:";
    } else {
        if (ossl_prov_bio_printf(out, "Public-Key: (%d bit)\n",
                                 BN_num_bits(rsa_n)) <= 0)
            goto err;
        modulus_label = "Modulus:";
        exponent_label = "Exponent:";
    }
    if (!ossl_prov_print_labeled_bignum(out, modulus_label, rsa_n))
        goto err;
    if (!ossl_prov_print_labeled_bignum(out, exponent_label, rsa_e))
        goto err;
    if (priv) {
        int i;

        if (!ossl_prov_print_labeled_bignum(out, "privateExponent:", rsa_d))
            goto err;
        if (!ossl_prov_print_labeled_bignum(out, "prime1:",
                                            sk_BIGNUM_const_value(factors, 0)))
            goto err;
        if (!ossl_prov_print_labeled_bignum(out, "prime2:",
                                            sk_BIGNUM_const_value(factors, 1)))
            goto err;
        if (!ossl_prov_print_labeled_bignum(out, "exponent1:",
                                            sk_BIGNUM_const_value(exps, 0)))
            goto err;
        if (!ossl_prov_print_labeled_bignum(out, "exponent2:",
                                            sk_BIGNUM_const_value(exps, 1)))
            goto err;
        if (!ossl_prov_print_labeled_bignum(out, "coefficient:",
                                            sk_BIGNUM_const_value(coeffs, 0)))
            goto err;
        for (i = 2; i < sk_BIGNUM_const_num(factors); i++) {
            if (ossl_prov_bio_printf(out, "prime%d:", i + 1) <= 0)
                goto err;
            if (!ossl_prov_print_labeled_bignum(out, NULL,
                                                sk_BIGNUM_const_value(factors,
                                                                      i)))
                goto err;
            if (ossl_prov_bio_printf(out, "exponent%d:", i + 1) <= 0)
                goto err;
            if (!ossl_prov_print_labeled_bignum(out, NULL,
                                                sk_BIGNUM_const_value(exps, i)))
                goto err;
            if (ossl_prov_bio_printf(out, "coefficient%d:", i + 1) <= 0)
                goto err;
            if (!ossl_prov_print_labeled_bignum(out, NULL,
                                                sk_BIGNUM_const_value(coeffs,
                                                                      i - 1)))
                goto err;
        }
    }
    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}

