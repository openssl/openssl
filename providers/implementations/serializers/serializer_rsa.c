/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include "internal/packet.h"
#include "crypto/rsa.h"           /* rsa_get0_all_params() */
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/der_rsa.h"         /* DER_w_RSASSA_PSS_params() */
#include "prov/implementations.h" /* rsa_keymgmt_functions */
#include "serializer_local.h"

DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

OSSL_FUNC_keymgmt_new_fn *ossl_prov_get_keymgmt_rsa_new(void)
{
    return ossl_prov_get_keymgmt_new(rsa_keymgmt_functions);
}

OSSL_FUNC_keymgmt_free_fn *ossl_prov_get_keymgmt_rsa_free(void)
{
    return ossl_prov_get_keymgmt_free(rsa_keymgmt_functions);
}

OSSL_FUNC_keymgmt_import_fn *ossl_prov_get_keymgmt_rsa_import(void)
{
    return ossl_prov_get_keymgmt_import(rsa_keymgmt_functions);
}

OSSL_FUNC_keymgmt_export_fn *ossl_prov_get_keymgmt_rsa_export(void)
{
    return ossl_prov_get_keymgmt_export(rsa_keymgmt_functions);
}

int ossl_prov_print_rsa(BIO *out, RSA *rsa, int priv)
{
    const char *modulus_label;
    const char *exponent_label;
    const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
    STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
    STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();
    RSA_PSS_PARAMS_30 *pss_params = rsa_get0_pss_params_30(rsa);
    int ret = 0;

    if (rsa == NULL || factors == NULL || exps == NULL || coeffs == NULL)
        goto err;

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    rsa_get0_all_params(rsa, factors, exps, coeffs);

    if (priv && rsa_d != NULL) {
        if (BIO_printf(out, "Private-Key: (%d bit, %d primes)\n",
                       BN_num_bits(rsa_n),
                       sk_BIGNUM_const_num(factors)) <= 0)
            goto err;
        modulus_label = "modulus:";
        exponent_label = "publicExponent:";
    } else {
        if (BIO_printf(out, "Public-Key: (%d bit)\n", BN_num_bits(rsa_n)) <= 0)
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
            if (BIO_printf(out, "prime%d:", i + 1) <= 0)
                goto err;
            if (!ossl_prov_print_labeled_bignum(out, NULL,
                                                sk_BIGNUM_const_value(factors,
                                                                      i)))
                goto err;
            if (BIO_printf(out, "exponent%d:", i + 1) <= 0)
                goto err;
            if (!ossl_prov_print_labeled_bignum(out, NULL,
                                                sk_BIGNUM_const_value(exps, i)))
                goto err;
            if (BIO_printf(out, "coefficient%d:", i + 1) <= 0)
                goto err;
            if (!ossl_prov_print_labeled_bignum(out, NULL,
                                                sk_BIGNUM_const_value(coeffs,
                                                                      i - 1)))
                goto err;
        }
    }

    switch (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        if (!rsa_pss_params_30_is_unrestricted(pss_params)) {
            if (BIO_printf(out, "(INVALID PSS PARAMETERS)\n") <= 0)
                goto err;
        }
        break;
    case RSA_FLAG_TYPE_RSASSAPSS:
        if (rsa_pss_params_30_is_unrestricted(pss_params)) {
            if (BIO_printf(out, "No PSS parameter restrictions\n") <= 0)
                goto err;
        } else {
            int hashalg_nid = rsa_pss_params_30_hashalg(pss_params);
            int maskgenalg_nid = rsa_pss_params_30_maskgenalg(pss_params);
            int maskgenhashalg_nid =
                rsa_pss_params_30_maskgenhashalg(pss_params);
            int saltlen = rsa_pss_params_30_saltlen(pss_params);
            int trailerfield = rsa_pss_params_30_trailerfield(pss_params);

            if (BIO_printf(out, "PSS parameter restrictions:\n") <= 0)
                goto err;
            if (BIO_printf(out, "  Hash Algorithm: %s%s\n",
                           rsa_oaeppss_nid2name(hashalg_nid),
                           (hashalg_nid == NID_sha1
                           ? " (default)" : "")) <= 0)
                goto err;
            if (BIO_printf(out, "  Mask Algorithm: %s with %s%s\n",
                           rsa_mgf_nid2name(maskgenalg_nid),
                           rsa_oaeppss_nid2name(maskgenhashalg_nid),
                           (maskgenalg_nid == NID_mgf1
                            && maskgenhashalg_nid == NID_sha1
                            ? " (default)" : "")) <= 0)
                goto err;
            if (BIO_printf(out, "  Minimum Salt Length: %d%s\n",
                           saltlen,
                           (saltlen == 20 ? " (default)" : "")) <= 0)
                goto err;
            /*
             * TODO(3.0) Should we show the ASN.1 trailerField value, or
             * the actual trailerfield byte (i.e. 0xBC for 1)?
             * crypto/rsa/rsa_ameth.c isn't very clear on that, as it
             * does display 0xBC when the default applies, but the ASN.1
             * trailerField value otherwise...
             */
            if (BIO_printf(out, "  Trailer Field: 0x%x%s\n",
                           trailerfield,
                           (trailerfield == 1 ? " (default)" : ""))
                <= 0)
                goto err;
        }
        break;
    }

    ret = 1;
 err:
    sk_BIGNUM_const_free(factors);
    sk_BIGNUM_const_free(exps);
    sk_BIGNUM_const_free(coeffs);
    return ret;
}

/*
 * Helper functions to prepare RSA-PSS params for serialization.  We would
 * have simply written the whole AlgorithmIdentifier, but existing libcrypto
 * functionality doesn't allow that.
 */

int ossl_prov_prepare_rsa_params(const void *rsa, int nid,
                                 void **pstr, int *pstrtype)
{
    const RSA_PSS_PARAMS_30 *pss = rsa_get0_pss_params_30((RSA *)rsa);

    *pstr = NULL;

    switch (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        /* If plain RSA, the parameters shall be NULL */
        *pstrtype = V_ASN1_NULL;
        return 1;
    case RSA_FLAG_TYPE_RSASSAPSS:
        if (rsa_pss_params_30_is_unrestricted(pss)) {
            *pstrtype = V_ASN1_UNDEF;
        } else {
            ASN1_STRING *astr = NULL;
            WPACKET pkt;
            unsigned char *str = NULL;
            size_t str_sz = 0;
            int i;

            for (i = 0; i < 2; i++) {
                switch (i) {
                case 0:
                    if (!WPACKET_init_null_der(&pkt))
                        goto err;
                    break;
                case 1:
                    if ((str = OPENSSL_malloc(str_sz)) == NULL
                        || !WPACKET_init_der(&pkt, str, str_sz)) {
                        goto err;
                    }
                    break;
                }
                if (!DER_w_RSASSA_PSS_params(&pkt, -1, pss)
                    || !WPACKET_finish(&pkt)
                    || !WPACKET_get_total_written(&pkt, &str_sz))
                    goto err;
                WPACKET_cleanup(&pkt);

                /*
                 * If no PSS parameters are going to be written, there's no
                 * point going for another iteration.
                 * This saves us from getting |str| allocated just to have it
                 * immediately de-allocated.
                 */
                if (str_sz == 0)
                    break;
            }

            if ((astr = ASN1_STRING_new()) == NULL)
                goto err;
            *pstrtype = V_ASN1_SEQUENCE;
            ASN1_STRING_set0(astr, str, (int)str_sz);
            *pstr = astr;

            return 1;
         err:
            OPENSSL_free(str);
            return 0;
        }
    }

    /* Currently unsupported RSA key type */
    return 0;
}

int ossl_prov_rsa_type_to_evp(const RSA *rsa)
{
    switch (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        return EVP_PKEY_RSA;
    case RSA_FLAG_TYPE_RSASSAPSS:
        return EVP_PKEY_RSA_PSS;
    }

    /* Currently unsupported RSA key type */
    return EVP_PKEY_NONE;
}
