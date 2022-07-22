/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_record_util.h"
#include "internal/quic_wire_pkt.h"
#include <openssl/kdf.h>
#include <openssl/core_names.h>

/*
 * QUIC Key Derivation Utilities
 * =============================
 */
#define MAX_LABEL_LEN     249

static const unsigned char label_prefix[] = {
    0x74, 0x6C, 0x73, 0x31, 0x33, 0x20 /* "tls13 " */
};

int ossl_quic_hkdf_extract(OSSL_LIB_CTX *libctx,
                           const char *propq,
                           const EVP_MD *md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *ikm, size_t ikm_len,
                           unsigned char *out, size_t out_len)
{
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[7], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;
    const char *md_name;

    if ((md_name = EVP_MD_get0_name(md)) == NULL
        || (kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_HKDF, propq)) == NULL
        || (kctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto err;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)md_name, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             (unsigned char *)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *)ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, out, out_len, params);

err:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

int ossl_quic_hkdf_expand_label(OSSL_LIB_CTX *libctx,
                                const char *propq,
                                const EVP_MD *md,
                                const unsigned char *secret, size_t secret_len,
                                const unsigned char *label, size_t label_len,
                                const unsigned char *ctx, size_t ctx_len,
                                unsigned char *out, size_t out_len)
{
    int ret = 0, md_len;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[7], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    const char *md_name;

    if (label_len > MAX_LABEL_LEN
        || (md_name = EVP_MD_get0_name(md)) == NULL
        || (md_len = EVP_MD_get_size(md)) <= 0
        || (size_t)md_len != secret_len
        || (kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_TLS1_3_KDF, propq)) == NULL
        || (kctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto err;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)md_name, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *)secret, secret_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX,
                                             (unsigned char *)label_prefix,
                                             sizeof(label_prefix));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL,
                                             (unsigned char *)label, label_len);
    if (ctx != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA,
                                                 (unsigned char *)ctx, ctx_len);

    *p++ = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, out, out_len, params);

err:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/*
 * QUIC Record Layer Ciphersuite Info
 * ==================================
 */

struct suite_info {
    const char *cipher_name, *md_name;
    uint32_t secret_len, cipher_key_len, cipher_iv_len, cipher_tag_len;
    uint32_t hdr_prot_key_len, hdr_prot_cipher_id;
};

static const struct suite_info suite_aes128gcm = {
    "AES-128-GCM", "SHA256", 32, 16, 12, 16, 16,
    QUIC_HDR_PROT_CIPHER_AES_128
};

static const struct suite_info suite_aes256gcm = {
    "AES-256-GCM", "SHA384", 48, 32, 12, 16, 32,
    QUIC_HDR_PROT_CIPHER_AES_256
};

static const struct suite_info suite_chacha20poly1305 = {
    "ChaCha20-Poly1305", "SHA256", 32, 32, 12, 16, 32,
    QUIC_HDR_PROT_CIPHER_CHACHA
};

static const struct suite_info *get_suite(uint32_t suite_id)
{
    switch (suite_id) {
        case QRL_SUITE_AES128GCM:
            return &suite_aes128gcm;
        case QRL_SUITE_AES256GCM:
            return &suite_aes256gcm;
        case QRL_SUITE_CHACHA20POLY1305:
            return &suite_chacha20poly1305;
        default:
            return NULL;
    }
}

const char *ossl_qrl_get_suite_cipher_name(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->cipher_name : NULL;
}

const char *ossl_qrl_get_suite_md_name(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->md_name : NULL;
}

uint32_t ossl_qrl_get_suite_secret_len(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->secret_len : 0;
}

uint32_t ossl_qrl_get_suite_cipher_key_len(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->cipher_key_len : 0;
}

uint32_t ossl_qrl_get_suite_cipher_iv_len(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->cipher_iv_len : 0;
}

uint32_t ossl_qrl_get_suite_cipher_tag_len(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->cipher_tag_len : 0;
}

uint32_t ossl_qrl_get_suite_hdr_prot_cipher_id(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->hdr_prot_cipher_id : 0;
}

uint32_t ossl_qrl_get_suite_hdr_prot_key_len(uint32_t suite_id)
{
    const struct suite_info *c = get_suite(suite_id);
    return c != NULL ? c->hdr_prot_key_len : 0;
}
