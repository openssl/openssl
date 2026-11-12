/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * A Merkle Tree Certificate cosigner a relying party trusts (sections 5.3
 * and 7.3 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/),
 * and the certificates that represent them.  See include/crypto/mtc_cosigner.h.
 *
 * A cosigner certificate carries the cosigner ID as the RELATIVE-OID subject
 * attribute of section 5.1 (experimental OID 1.3.6.1.4.1.44363.47.3) and the
 * cosigner's public key, and no id-pe-mtcCertificationAuthority-SHA256
 * extension: that extension marks a CA certificate (section 5.5).
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>
#include <openssl/x509.h>

#include "crypto/mtc_ca.h"
#include "crypto/mtc_cosigner.h"
#include "crypto/mtc_verify.h"

OSSL_MTC_COSIGNER *ossl_mtc_cosigner_new(const uint8_t *id, size_t id_len,
    EVP_PKEY *pkey)
{
    OSSL_MTC_COSIGNER *cosigner;

    /* A TrustAnchorID is 1 to 255 bytes. */
    if (id_len == 0 || id_len > 255)
        return NULL;

    if ((cosigner = OPENSSL_zalloc(sizeof(*cosigner))) == NULL)
        return NULL;
    /*
     * The reference on pkey is taken last: until it is recorded there is
     * nothing for ossl_mtc_cosigner_free() to release.
     */
    if ((cosigner->id = OPENSSL_memdup(id, id_len)) == NULL
        || !EVP_PKEY_up_ref(pkey)) {
        ossl_mtc_cosigner_free(cosigner);
        return NULL;
    }
    cosigner->id_len = id_len;
    cosigner->pkey = pkey;
    return cosigner;
}

void ossl_mtc_cosigner_free(OSSL_MTC_COSIGNER *cosigner)
{
    if (cosigner == NULL)
        return;
    OPENSSL_free(cosigner->id);
    EVP_PKEY_free(cosigner->pkey);
    OPENSSL_free(cosigner);
}

const uint8_t *ossl_mtc_cosigner_id(const OSSL_MTC_COSIGNER *cosigner,
    size_t *len)
{
    *len = cosigner->id_len;
    return cosigner->id;
}

EVP_PKEY *ossl_mtc_cosigner_pkey(const OSSL_MTC_COSIGNER *cosigner)
{
    return cosigner->pkey;
}

int OSSL_MTC_COSIGNER_cmp(const OSSL_MTC_COSIGNER *const *a,
    const OSSL_MTC_COSIGNER *const *b)
{
    size_t alen, blen;
    const uint8_t *aid = ossl_mtc_cosigner_id(*a, &alen);
    const uint8_t *bid = ossl_mtc_cosigner_id(*b, &blen);

    return ossl_mtc_id_order(aid, alen, bid, blen);
}

int ossl_mtc_cosigner_stack_add(STACK_OF(OSSL_MTC_COSIGNER) *cosigners,
    OSSL_MTC_COSIGNER *cosigner)
{
    int idx = 0;

    if (sk_OSSL_MTC_COSIGNER_num(cosigners) > 0) {
        size_t alen, blen;
        const uint8_t *aid, *bid;
        int c;

        idx = sk_OSSL_MTC_COSIGNER_find_ex(cosigners, cosigner);
        aid = ossl_mtc_cosigner_id(sk_OSSL_MTC_COSIGNER_value(cosigners, idx),
            &alen);
        bid = ossl_mtc_cosigner_id(cosigner, &blen);
        c = ossl_mtc_id_order(aid, alen, bid, blen);
        if (c == 0)
            return 0; /* duplicate cosigner ID */
        if (c < 0)
            idx++;
    }
    return sk_OSSL_MTC_COSIGNER_insert(cosigners, cosigner, idx) > 0;
}

OSSL_MTC_COSIGNER *ossl_mtc_cosigner_stack_lookup(
    const STACK_OF(OSSL_MTC_COSIGNER) *cosigners, const uint8_t *id,
    size_t id_len)
{
    OSSL_MTC_COSIGNER key;
    int idx;

    if (cosigners == NULL)
        return NULL;
    memset(&key, 0, sizeof(key));
    key.id = (uint8_t *)id;
    key.id_len = id_len;
    idx = sk_OSSL_MTC_COSIGNER_find(cosigners, &key);
    return idx < 0 ? NULL : sk_OSSL_MTC_COSIGNER_value(cosigners, idx);
}

/* Build a cosigner from one certificate and push it onto the stack in arg. */
static int push_cosigner(OSSL_LIB_CTX *libctx, const char *propq, X509 *cert,
    void *arg)
{
    STACK_OF(OSSL_MTC_COSIGNER) *out_cosigners = arg;
    OSSL_MTC_COSIGNER *cosigner = NULL;
    uint8_t *id = NULL;
    size_t id_len = 0;
    EVP_PKEY *pkey;
    int ret = 0;

    /* A CA certificate (5.5) is not a cosigner certificate. */
    if (ossl_mtc_cert_is_ca(cert)
        || !ossl_mtc_ca_id_from_name(X509_get_subject_name(cert), &id, &id_len)
        || (pkey = X509_get0_pubkey(cert)) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if ((cosigner = ossl_mtc_cosigner_new(id, id_len, pkey)) == NULL
        || sk_OSSL_MTC_COSIGNER_push(out_cosigners, cosigner) <= 0) {
        ossl_mtc_cosigner_free(cosigner);
        goto err;
    }
    ret = 1;
err:
    OPENSSL_free(id);
    return ret;
}

/* Public API. */

OSSL_MTC_COSIGNER *OSSL_MTC_COSIGNER_new(const uint8_t *id, size_t id_len,
    EVP_PKEY *pkey)
{
    if (id == NULL || pkey == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return ossl_mtc_cosigner_new(id, id_len, pkey);
}

void OSSL_MTC_COSIGNER_free(OSSL_MTC_COSIGNER *cosigner)
{
    ossl_mtc_cosigner_free(cosigner);
}

int OSSL_MTC_COSIGNER_parse_certificates(OSSL_LIB_CTX *libctx,
    const char *propq, BIO *in, STACK_OF(OSSL_MTC_COSIGNER) *out_cosigners)
{
    int start;

    if (in == NULL || out_cosigners == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Remember the starting size so a failure leaves out_cosigners unchanged. */
    start = sk_OSSL_MTC_COSIGNER_num(out_cosigners);
    if (ossl_mtc_parse_pem_certificates(libctx, propq, in, push_cosigner,
            out_cosigners))
        return 1;
    while (sk_OSSL_MTC_COSIGNER_num(out_cosigners) > start)
        OSSL_MTC_COSIGNER_free(sk_OSSL_MTC_COSIGNER_pop(out_cosigners));
    return 0;
}

int OSSL_MTC_COSIGNER_get0_id(const OSSL_MTC_COSIGNER *cosigner,
    const uint8_t **out_id, size_t *out_id_len)
{
    if (cosigner == NULL || out_id == NULL || out_id_len == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *out_id = ossl_mtc_cosigner_id(cosigner, out_id_len);
    return 1;
}
