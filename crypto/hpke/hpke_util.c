/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/hpke.h"
#include "internal/packet.h"

/*
 * The largest value happens inside dhkem_extract_and_expand
 * Which consists of a max dkmlen of 2*privkeylen + suiteid + small label
 */
#define LABELED_EXTRACT_SIZE (10 + 12 + 2 * OSSL_HPKE_MAX_PRIVATE)

/*
 * The largest value happens inside dhkem_extract_and_expand
 * Which consists of a prklen of secretlen + contextlen of 3 encoded public keys
 * + suiteid + small label
 */
#define LABELED_EXPAND_SIZE (LABELED_EXTRACT_SIZE + 3 * OSSL_HPKE_MAX_PUBLIC)

/* ASCII: "HPKE-v1", in hex for EBCDIC compatibility */
static const char LABEL_HPKEV1[] = "\x48\x50\x4B\x45\x2D\x76\x31";

static int kdf_derive(EVP_KDF_CTX *kctx,
                      unsigned char *out, size_t outlen, int mode,
                      const unsigned char *salt, size_t saltlen,
                      const unsigned char *ikm, size_t ikmlen,
                      const unsigned char *info, size_t infolen)
{
    int ret;
    OSSL_PARAM params[5], *p = params;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    if (salt != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (char *)salt, saltlen);
    if (ikm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (char *)ikm, ikmlen);
    if (info != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 (char *)info, infolen);
    *p = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
    return ret;
}

int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
                          unsigned char *prk, size_t prklen,
                          const unsigned char *salt, size_t saltlen,
                          const unsigned char *ikm, size_t ikmlen)
{
    return kdf_derive(kctx, prk, prklen, EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
                      salt, saltlen, ikm, ikmlen, NULL, 0);
}

/* Common code to perform a HKDF expand */
int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
                         unsigned char *okm, size_t okmlen,
                         const unsigned char *prk, size_t prklen,
                         const unsigned char *info, size_t infolen)
{
    return kdf_derive(kctx, okm, okmlen, EVP_KDF_HKDF_MODE_EXPAND_ONLY,
                      NULL, 0, prk, prklen, info, infolen);
}

/*
 * See RFC 9180 Section 4 LabelExtract()
 */
int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
                              unsigned char *prk, size_t prklen,
                              const unsigned char *salt, size_t saltlen,
                              const unsigned char *suiteid, size_t suiteidlen,
                              const char *label,
                              const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    size_t labeled_ikmlen = 0;
    unsigned char labeled_ikm[LABELED_EXTRACT_SIZE];
    WPACKET pkt;

    /* labeled_ikm = concat("HPKE-v1", suiteid, label, ikm) */
    if (!WPACKET_init_static_len(&pkt, labeled_ikm, sizeof(labeled_ikm), 0)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, ikm, ikmlen)
            || !WPACKET_get_total_written(&pkt, &labeled_ikmlen)
            || !WPACKET_finish(&pkt)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }

    ret = ossl_hpke_kdf_extract(kctx, prk, prklen, salt, saltlen,
                                labeled_ikm, labeled_ikmlen);
end:
    WPACKET_cleanup(&pkt);
    OPENSSL_cleanse(labeled_ikm, labeled_ikmlen);
    return ret;
}

/*
 * See RFC 9180 Section 4 LabelExpand()
 */
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
                             unsigned char *okm, size_t okmlen,
                             const unsigned char *prk, size_t prklen,
                             const unsigned char *suiteid, size_t suiteidlen,
                             const char *label,
                             const unsigned char *info, size_t infolen)
{
    int ret = 0;
    size_t labeled_infolen = 0;
    unsigned char labeled_info[LABELED_EXPAND_SIZE];
    WPACKET pkt;

    /* labeled_info = concat(okmlen, "HPKE-v1", suiteid, label, info) */
    if (!WPACKET_init_static_len(&pkt, labeled_info, sizeof(labeled_info), 0)
            || !WPACKET_put_bytes_u16(&pkt, okmlen)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, info, infolen)
            || !WPACKET_get_total_written(&pkt, &labeled_infolen)
            || !WPACKET_finish(&pkt)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }

    ret = ossl_hpke_kdf_expand(kctx, okm, okmlen,
                               prk, prklen, labeled_info, labeled_infolen);
end:
    WPACKET_cleanup(&pkt);
    return ret;
}

/* Common code to create a HKDF ctx */
EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(libctx, kdfname, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx != NULL && mdname != NULL) {
        OSSL_PARAM params[3], *p = params;

        if (mdname != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                    (char *)mdname, 0);
        if (propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES,
                                                    (char *)propq, 0);
        *p = OSSL_PARAM_construct_end();
        if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
            EVP_KDF_CTX_free(kctx);
            return NULL;
        }
    }
    return kctx;
}
