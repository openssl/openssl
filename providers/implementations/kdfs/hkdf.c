/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "internal/deprecated.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "internal/packet.h"
#include "crypto/evp.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"
#include "prov/securitycheck.h"
#include "internal/e_os.h"
#include "internal/fips.h"
#include "internal/params.h"
#include "internal/sizes.h"

#define HKDF_MAXBUF 2048
#define HKDF_MAXINFO (32 * 1024)
#define HKDF_MAX_INFOS 5

static OSSL_FUNC_kdf_newctx_fn kdf_hkdf_new;
static OSSL_FUNC_kdf_dupctx_fn kdf_hkdf_dup;
static OSSL_FUNC_kdf_freectx_fn kdf_hkdf_free;
static OSSL_FUNC_kdf_reset_fn kdf_hkdf_reset;
static OSSL_FUNC_kdf_derive_fn kdf_hkdf_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_hkdf_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_hkdf_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn hkdf_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn hkdf_common_get_ctx_params;
static OSSL_FUNC_kdf_derive_fn kdf_tls1_3_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_tls1_3_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_tls1_3_set_ctx_params;
static OSSL_FUNC_kdf_derive_multi_fn kdf_tls1_3_derive_multi;
static OSSL_FUNC_kdf_get_skey_fn kdf_tls1_3_get_skey;
static OSSL_FUNC_kdf_get_iv_fn kdf_tls1_3_get_iv;

typedef struct kdf_hkdf_st KDF_HKDF;
static void kdf_tls1_3_multi_cleanup(KDF_HKDF *ctx);

/*
 * TLS 1.3 derives one key and one IV from a traffic secret; the secret
 * already encodes the direction, so the client and server purposes name the
 * same key and differ only in the type the caller may request.
 */
#define TLS13_NUM_KEYS 2
static OSSL_FUNC_kdf_newctx_fn kdf_hkdf_sha256_new;
static OSSL_FUNC_kdf_newctx_fn kdf_hkdf_sha384_new;
static OSSL_FUNC_kdf_newctx_fn kdf_hkdf_sha512_new;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_hkdf_fixed_digest_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_hkdf_fixed_digest_set_ctx_params;

static void *kdf_hkdf_fixed_digest_new(void *provctx, const char *digest);
static void kdf_hkdf_reset_ex(void *vctx, int on_free);

static int HKDF(OSSL_LIB_CTX *libctx, const EVP_MD *evp_md,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *key, size_t key_len,
    const unsigned char *info, size_t info_len,
    unsigned char *okm, size_t okm_len);
static int HKDF_Extract(OSSL_LIB_CTX *libctx, const EVP_MD *evp_md,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len,
    unsigned char *prk, size_t prk_len);
static int HKDF_Expand(const EVP_MD *evp_md,
    const unsigned char *prk, size_t prk_len,
    const unsigned char *info, size_t info_len,
    unsigned char *okm, size_t okm_len);

struct kdf_hkdf_st {
    void *provctx;
    int mode;
    PROV_DIGEST digest;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char *prefix;
    size_t prefix_len;
    unsigned char *label;
    size_t label_len;
    unsigned char *data;
    size_t data_len;
    unsigned char *info;
    size_t info_len;
    int fixed_digest;

    /* Multi-key derivation configuration */
    size_t cipher_key_len;
    size_t iv_len;
    /*
     * The cipher the derived key is for, resolved at set time to just the
     * two facts needed of it: the name, which decides the key type, and the
     * key length.  The EVP_CIPHER itself is not kept.
     *
     * The length is deliberately *not* merged into cipher_key_len above.
     * That one is what the caller asked for, this one is what the cipher
     * requires, and derive_multi() compares them -- naming AES-128-CBC and a
     * cipher_key_len of 10 is a contradiction worth reporting rather than
     * silently resolving.  Keeping them apart is also what lets a later
     * "cipher" replace an earlier one while a caller-supplied length still
     * conflicts with it, whatever order the two arrive in.
     */
    char *multi_cipher_name;
    size_t multi_cipher_keylen;

    /*
     * Result of a multi-key derivation, released by kdf_hkdf_reset_ex() and
     * copied by kdf_hkdf_dup().
     */
    struct {
        unsigned char *key;
        size_t key_len;
        unsigned char *iv;
        size_t iv_len;
        char *cipher_key_type;
    } multi;

    OSSL_FIPS_IND_DECLARE
};

static void *kdf_hkdf_new(void *provctx)
{
    KDF_HKDF *ctx;

    if (!ossl_prov_is_running())
        return NULL;

#ifdef FIPS_MODULE
    if (!ossl_deferred_self_test(PROV_LIBCTX_OF(provctx),
            ST_ID_KDF_HKDF))
        return NULL;
#endif

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) != NULL) {
        ctx->provctx = provctx;
        OSSL_FIPS_IND_INIT(ctx)
    }
    return ctx;
}

static void kdf_hkdf_free(void *vctx)
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;

    if (ctx != NULL) {
        kdf_hkdf_reset_ex(vctx, 1);
        OPENSSL_free(ctx);
    }
}

static void kdf_hkdf_reset(void *vctx)
{
    kdf_hkdf_reset_ex(vctx, 0);
}

static void kdf_hkdf_reset_ex(void *vctx, int on_free)
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;
    void *provctx = ctx->provctx;
    int preserve_digest = on_free ? 0 : ctx->fixed_digest;
    PROV_DIGEST save_prov_digest = { 0 };

    /* For fixed digests just save and restore the PROV_DIGEST object */
    if (preserve_digest)
        save_prov_digest = ctx->digest;
    else
        ossl_prov_digest_reset(&ctx->digest);
#ifdef OPENSSL_PEDANTIC_ZEROIZATION
    OPENSSL_clear_free(ctx->salt, ctx->salt_len);
#else
    OPENSSL_free(ctx->salt);
#endif
    OPENSSL_free(ctx->prefix);
    OPENSSL_free(ctx->label);
    OPENSSL_clear_free(ctx->data, ctx->data_len);
    OPENSSL_clear_free(ctx->key, ctx->key_len);
    OPENSSL_clear_free(ctx->info, ctx->info_len);
    OPENSSL_free(ctx->multi_cipher_name);
    kdf_tls1_3_multi_cleanup(ctx);
    memset(ctx, 0, sizeof(*ctx));
    ctx->provctx = provctx;
    if (preserve_digest) {
        ctx->fixed_digest = preserve_digest;
        ctx->digest = save_prov_digest;
    }
}

static void *kdf_hkdf_dup(void *vctx)
{
    const KDF_HKDF *src = (const KDF_HKDF *)vctx;
    KDF_HKDF *dest;

    dest = kdf_hkdf_new(src->provctx);
    if (dest != NULL) {
        if (!ossl_prov_memdup(src->salt, src->salt_len, &dest->salt,
                &dest->salt_len)
            || !ossl_prov_memdup(src->key, src->key_len,
                &dest->key, &dest->key_len)
            || !ossl_prov_memdup(src->prefix, src->prefix_len,
                &dest->prefix, &dest->prefix_len)
            || !ossl_prov_memdup(src->label, src->label_len,
                &dest->label, &dest->label_len)
            || !ossl_prov_memdup(src->data, src->data_len,
                &dest->data, &dest->data_len)
            || !ossl_prov_memdup(src->info, src->info_len,
                &dest->info, &dest->info_len)
            || !ossl_prov_digest_copy(&dest->digest, &src->digest))
            goto err;
        if (src->multi_cipher_name != NULL
            && (dest->multi_cipher_name = OPENSSL_strdup(src->multi_cipher_name)) == NULL)
            goto err;
        dest->multi_cipher_keylen = src->multi_cipher_keylen;
        if (!ossl_prov_memdup(src->multi.key, src->multi.key_len,
                &dest->multi.key, &dest->multi.key_len)
            || !ossl_prov_memdup(src->multi.iv, src->multi.iv_len,
                &dest->multi.iv, &dest->multi.iv_len))
            goto err;
        if (src->multi.cipher_key_type != NULL
            && (dest->multi.cipher_key_type = OPENSSL_strdup(src->multi.cipher_key_type)) == NULL)
            goto err;
        dest->cipher_key_len = src->cipher_key_len;
        dest->iv_len = src->iv_len;
        dest->mode = src->mode;
        dest->fixed_digest = src->fixed_digest;
        OSSL_FIPS_IND_COPY(dest, src)
    }
    return dest;

err:
    kdf_hkdf_free(dest);
    return NULL;
}

static size_t kdf_hkdf_size(KDF_HKDF *ctx)
{
    int sz;
    const EVP_MD *md = ossl_prov_digest_md(&ctx->digest);

    if (ctx->mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
        return SIZE_MAX;

    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    sz = EVP_MD_get_size(md);
    if (sz <= 0)
        return 0;

    return sz;
}

#ifdef FIPS_MODULE
static int fips_hkdf_key_check_passed(KDF_HKDF *ctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(ctx->provctx);
    int key_approved = ossl_kdf_check_key_size(ctx->key_len);

    if (!key_approved) {
        if (!OSSL_FIPS_IND_ON_UNAPPROVED(ctx, OSSL_FIPS_IND_SETTABLE0,
                libctx, "HKDF", "Key size",
                FIPS_CONFIG_HKDF_KEY_CHECK)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    return 1;
}
#endif

static int kdf_hkdf_derive(void *vctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(ctx->provctx);
    const EVP_MD *md;

    if (!ossl_prov_is_running() || !kdf_hkdf_set_ctx_params(ctx, params))
        return 0;

    md = ossl_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    switch (ctx->mode) {
    case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
    default:
        return HKDF(libctx, md, ctx->salt, ctx->salt_len,
            ctx->key, ctx->key_len, ctx->info, ctx->info_len, key, keylen);

    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        return HKDF_Extract(libctx, md, ctx->salt, ctx->salt_len,
            ctx->key, ctx->key_len, key, keylen);

    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        return HKDF_Expand(md, ctx->key, ctx->key_len, ctx->info,
            ctx->info_len, key, keylen);
    }
}

struct hkdf_all_set_ctx_params_st {
    OSSL_PARAM *mode;
    OSSL_PARAM *propq;
    OSSL_PARAM *digest;
    OSSL_PARAM *key;
    OSSL_PARAM *salt;
#ifdef FIPS_MODULE
    OSSL_PARAM *ind_k;
    OSSL_PARAM *ind_d;
#endif
    OSSL_PARAM *prefix;
    OSSL_PARAM *label;
    OSSL_PARAM *data;
    OSSL_PARAM *info[HKDF_MAX_INFOS];
    int num_info;
    OSSL_PARAM *cipher_key_len;
    OSSL_PARAM *iv_len;
    OSSL_PARAM *cipher;
};

#define hkdf_set_ctx_params_st hkdf_all_set_ctx_params_st
#define hkdf_fixed_digest_set_ctx_params_st hkdf_all_set_ctx_params_st
#define kdf_tls1_3_set_ctx_params_st hkdf_all_set_ctx_params_st

#include "providers/implementations/kdfs/hkdf.inc"

static int hkdf_common_set_ctx_params(KDF_HKDF *ctx, struct hkdf_all_set_ctx_params_st *p)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(ctx->provctx);
    int n;

    if (p->digest != NULL) {
        const EVP_MD *md = NULL;

        if (!ossl_prov_digest_load(&ctx->digest, p->digest, p->propq, libctx))
            return 0;

        md = ossl_prov_digest_md(&ctx->digest);
        if (EVP_MD_xof(md)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED);
            return 0;
        }
    }

    if (p->mode != NULL) {
        if (p->mode->data_type == OSSL_PARAM_UTF8_STRING) {
            if (OPENSSL_strcasecmp(p->mode->data, "EXTRACT_AND_EXPAND") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            } else if (OPENSSL_strcasecmp(p->mode->data, "EXTRACT_ONLY") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            } else if (OPENSSL_strcasecmp(p->mode->data, "EXPAND_ONLY") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            } else {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
        } else if (OSSL_PARAM_get_int(p->mode, &n)) {
            if (n != EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                && n != EVP_KDF_HKDF_MODE_EXTRACT_ONLY
                && n != EVP_KDF_HKDF_MODE_EXPAND_ONLY) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
            ctx->mode = n;
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return 0;
        }
    }

    if (p->key != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->key_len);
        ctx->key = NULL;
        if (!OSSL_PARAM_get_octet_string(p->key, (void **)&ctx->key, 0,
                &ctx->key_len))
            return 0;
    }

    if (p->salt != NULL) {
        OPENSSL_free(ctx->salt);
        ctx->salt = NULL;
        if (!OSSL_PARAM_get_octet_string(p->salt, (void **)&ctx->salt, 0,
                &ctx->salt_len))
            return 0;
    }

    /* Only relevant for HKDF not to the TLS 1.3 KDF */
    if (ossl_param_get1_concat_octet_string(p->num_info, p->info,
            &ctx->info, &ctx->info_len)
        == 0)
        return 0;

    return 1;
}

static int kdf_hkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct hkdf_all_set_ctx_params_st p;
    KDF_HKDF *ctx = vctx;

    if (ctx == NULL || !hkdf_set_ctx_params_decoder(params, &p))
        return 0;

    if (!OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, OSSL_FIPS_IND_SETTABLE0, p.ind_k))
        return 0;

    if (!hkdf_common_set_ctx_params(ctx, &p))
        return 0;

#ifdef FIPS_MODULE
    if (p.key != NULL)
        if (!fips_hkdf_key_check_passed(ctx))
            return 0;
#endif

    return 1;
}

static const OSSL_PARAM *kdf_hkdf_settable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return hkdf_set_ctx_params_list;
}

static const OSSL_PARAM *hkdf_gettable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return hkdf_get_ctx_params_list;
}

static int hkdf_common_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;
    struct hkdf_get_ctx_params_st p;

    if (ctx == NULL || !hkdf_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.size != NULL) {
        size_t sz = kdf_hkdf_size(ctx);

        if (sz == 0)
            return 0;
        if (!OSSL_PARAM_set_size_t(p.size, sz))
            return 0;
    }

    if (p.digest != NULL) {
        const EVP_MD *md = ossl_prov_digest_md(&ctx->digest);

        if (md == NULL)
            return 0;
        else if (!OSSL_PARAM_set_utf8_string(p.digest, EVP_MD_get0_name(md)))
            return 0;
    }

    /*
     * Key type settled on by a preceding multi-key derivation.  Both purposes
     * name the same key, since a TLS 1.3 traffic secret already encodes the
     * direction.  Failing reports that no key was derived.
     */
    if (p.client_key_type != NULL || p.server_key_type != NULL) {
        OSSL_PARAM *out = p.client_key_type != NULL ? p.client_key_type
                                                    : p.server_key_type;

        if (ctx->multi.key == NULL
            || !OSSL_PARAM_set_utf8_string(out, ctx->multi.cipher_key_type))
            return 0;
        if (p.client_key_type != NULL && p.server_key_type != NULL
            && !OSSL_PARAM_set_utf8_string(p.server_key_type,
                ctx->multi.cipher_key_type))
            return 0;
    }

    /* OSSL_KDF_PARAM_MODE has multiple parameter types, so look for all instances */
    if (p.mode != NULL) {
        if (p.mode->data_type == OSSL_PARAM_UTF8_STRING) {
            switch (ctx->mode) {
            case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
                if (!OSSL_PARAM_set_utf8_string(p.mode, "EXTRACT_AND_EXPAND"))
                    return 0;
                break;
            case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
                if (!OSSL_PARAM_set_utf8_string(p.mode, "EXTRACT_ONLY"))
                    return 0;
                break;
            case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
                if (!OSSL_PARAM_set_utf8_string(p.mode, "EXPAND_ONLY"))
                    return 0;
                break;
            default:
                return 0;
            }
        } else {
            if (!OSSL_PARAM_set_int(p.mode, ctx->mode))
                return 0;
        }
    }

    if (p.salt != NULL) {
        if (ctx->salt == NULL || ctx->salt_len == 0)
            p.salt->return_size = 0;
        else if (!OSSL_PARAM_set_octet_string(p.salt, ctx->salt, ctx->salt_len))
            return 0;
    }

    if (p.info != NULL) {
        if (ctx->info == NULL || ctx->info_len == 0)
            p.info->return_size = 0;
        else if (!OSSL_PARAM_set_octet_string(p.info, ctx->info, ctx->info_len))
            return 0;
    }

    if (!OSSL_FIPS_IND_GET_CTX_FROM_PARAM(ctx, p.ind))
        return 0;

    return 1;
}

const OSSL_DISPATCH ossl_kdf_hkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))kdf_hkdf_new },
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void))kdf_hkdf_dup },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))kdf_hkdf_free },
    { OSSL_FUNC_KDF_RESET, (void (*)(void))kdf_hkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))kdf_hkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        (void (*)(void))kdf_hkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))kdf_hkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        (void (*)(void))hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))hkdf_common_get_ctx_params },
    OSSL_DISPATCH_END
};

static void *kdf_hkdf_fixed_digest_new(void *provctx, const char *digest)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    KDF_HKDF *ctx;
    OSSL_PARAM param;

    ctx = kdf_hkdf_new(provctx);
    if (ctx == NULL)
        return NULL;

    param = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST,
        (char *)digest, 0);
    if (!ossl_prov_digest_load(&ctx->digest, &param, NULL, libctx)) {
        kdf_hkdf_free(ctx);
        return NULL;
    }

    /* Now the digest can no longer be changed */
    ctx->fixed_digest = 1;

    return ctx;
}

static int kdf_hkdf_fixed_digest_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct hkdf_all_set_ctx_params_st p;
    KDF_HKDF *ctx = vctx;

    if (ctx == NULL || !hkdf_fixed_digest_set_ctx_params_decoder(params, &p))
        return 0;

    if (!OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, OSSL_FIPS_IND_SETTABLE0, p.ind_k))
        return 0;

    if (!hkdf_common_set_ctx_params(ctx, &p))
        return 0;

#ifdef FIPS_MODULE
    if (p.key != NULL)
        if (!fips_hkdf_key_check_passed(ctx))
            return 0;
#endif

    return 1;
}

static const OSSL_PARAM *kdf_hkdf_fixed_digest_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return hkdf_fixed_digest_set_ctx_params_list;
}

#define KDF_HKDF_FIXED_DIGEST_NEW(hashname, hashstring)        \
    static void *kdf_hkdf_##hashname##_new(void *provctx)      \
    {                                                          \
        return kdf_hkdf_fixed_digest_new(provctx, hashstring); \
    }

KDF_HKDF_FIXED_DIGEST_NEW(sha256, "SHA256")
KDF_HKDF_FIXED_DIGEST_NEW(sha384, "SHA384")
KDF_HKDF_FIXED_DIGEST_NEW(sha512, "SHA512")

#define MAKE_KDF_HKDF_FIXED_DIGEST_FUNCTIONS(hashname)                                                    \
    const OSSL_DISPATCH ossl_kdf_hkdf_##hashname##_functions[] = {                                        \
        { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))kdf_hkdf_##hashname##_new },                              \
        { OSSL_FUNC_KDF_DUPCTX, (void (*)(void))kdf_hkdf_dup },                                           \
        { OSSL_FUNC_KDF_FREECTX, (void (*)(void))kdf_hkdf_free },                                         \
        { OSSL_FUNC_KDF_RESET, (void (*)(void))kdf_hkdf_reset },                                          \
        { OSSL_FUNC_KDF_DERIVE, (void (*)(void))kdf_hkdf_derive },                                        \
        { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))kdf_hkdf_fixed_digest_settable_ctx_params }, \
        { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))kdf_hkdf_fixed_digest_set_ctx_params },           \
        { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))hkdf_gettable_ctx_params },                  \
        { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))hkdf_common_get_ctx_params },                     \
        OSSL_DISPATCH_END                                                                                 \
    };

MAKE_KDF_HKDF_FIXED_DIGEST_FUNCTIONS(sha256)
MAKE_KDF_HKDF_FIXED_DIGEST_FUNCTIONS(sha384)
MAKE_KDF_HKDF_FIXED_DIGEST_FUNCTIONS(sha512)

/*
 * Refer to "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
 * Section 2 (https://tools.ietf.org/html/rfc5869#section-2) and
 * "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
 * Section 4.2 (https://eprint.iacr.org/2010/264.pdf).
 *
 * From the paper:
 *   The scheme HKDF is specified as:
 *     HKDF(XTS, SKM, CTXinfo, L) = K(1) | K(2) | ... | K(t)
 *
 *     where:
 *       SKM is source key material
 *       XTS is extractor salt (which may be null or constant)
 *       CTXinfo is context information (may be null)
 *       L is the number of key bits to be produced by KDF
 *       k is the output length in bits of the hash function used with HMAC
 *       t = ceil(L/k)
 *       the value K(t) is truncated to its first d = L mod k bits.
 *
 * From RFC 5869:
 *   2.2.  Step 1: Extract
 *     HKDF-Extract(salt, IKM) -> PRK
 *   2.3.  Step 2: Expand
 *     HKDF-Expand(PRK, info, L) -> OKM
 */
static int HKDF(OSSL_LIB_CTX *libctx, const EVP_MD *evp_md,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len,
    const unsigned char *info, size_t info_len,
    unsigned char *okm, size_t okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    int ret, sz;
    size_t prk_len;

    sz = EVP_MD_get_size(evp_md);
    if (sz <= 0)
        return 0;
    prk_len = (size_t)sz;

    /* Step 1: HKDF-Extract(salt, IKM) -> PRK */
    if (!HKDF_Extract(libctx, evp_md,
            salt, salt_len, ikm, ikm_len, prk, prk_len))
        return 0;

    /* Step 2: HKDF-Expand(PRK, info, L) -> OKM */
    ret = HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(prk, sizeof(prk));

    return ret;
}

/*
 * Refer to "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
 * Section 2.2 (https://tools.ietf.org/html/rfc5869#section-2.2).
 *
 * 2.2.  Step 1: Extract
 *
 *   HKDF-Extract(salt, IKM) -> PRK
 *
 *   Options:
 *      Hash     a hash function; HashLen denotes the length of the
 *               hash function output in octets
 *
 *   Inputs:
 *      salt     optional salt value (a non-secret random value);
 *               if not provided, it is set to a string of HashLen zeros.
 *      IKM      input keying material
 *
 *   Output:
 *      PRK      a pseudorandom key (of HashLen octets)
 *
 *   The output PRK is calculated as follows:
 *
 *   PRK = HMAC-Hash(salt, IKM)
 */
static int HKDF_Extract(OSSL_LIB_CTX *libctx, const EVP_MD *evp_md,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len,
    unsigned char *prk, size_t prk_len)
{
    int sz = EVP_MD_get_size(evp_md);

    if (sz <= 0)
        return 0;
    if (prk_len != (size_t)sz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_OUTPUT_BUFFER_SIZE);
        return 0;
    }
    /* calc: PRK = HMAC-Hash(salt, IKM) */
    return EVP_Q_mac(libctx, "HMAC", NULL, EVP_MD_get0_name(evp_md), NULL, salt,
               salt_len, ikm, ikm_len, prk, EVP_MD_get_size(evp_md), NULL)
        != NULL;
}

/*
 * Refer to "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
 * Section 2.3 (https://tools.ietf.org/html/rfc5869#section-2.3).
 *
 * 2.3.  Step 2: Expand
 *
 *   HKDF-Expand(PRK, info, L) -> OKM
 *
 *   Options:
 *      Hash     a hash function; HashLen denotes the length of the
 *               hash function output in octets
 *
 *   Inputs:
 *      PRK      a pseudorandom key of at least HashLen octets
 *               (usually, the output from the extract step)
 *      info     optional context and application specific information
 *               (can be a zero-length string)
 *      L        length of output keying material in octets
 *               (<= 255*HashLen)
 *
 *   Output:
 *      OKM      output keying material (of L octets)
 *
 *   The output OKM is calculated as follows:
 *
 *   N = ceil(L/HashLen)
 *   T = T(1) | T(2) | T(3) | ... | T(N)
 *   OKM = first L octets of T
 *
 *   where:
 *   T(0) = empty string (zero length)
 *   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 *   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 *   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
 *   ...
 *
 *   (where the constant concatenated to the end of each T(n) is a
 *   single octet.)
 */
static int HKDF_Expand(const EVP_MD *evp_md,
    const unsigned char *prk, size_t prk_len,
    const unsigned char *info, size_t info_len,
    unsigned char *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    int ret = 0, sz;
    unsigned int i;
    unsigned char prev[EVP_MAX_MD_SIZE];
    size_t done_len = 0, dig_len, n;

    sz = EVP_MD_get_size(evp_md);
    if (sz <= 0)
        return 0;
    dig_len = (size_t)sz;

    /* calc: N = ceil(L/HashLen) */
    n = okm_len / dig_len;
    if (okm_len % dig_len)
        n++;

    if (n > 255 || okm == NULL)
        return 0;

    if ((hmac = HMAC_CTX_new()) == NULL)
        return 0;

    if (!HMAC_Init_ex(hmac, prk, (int)prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const unsigned char ctr = i;

        /* calc: T(i) = HMAC-Hash(PRK, T(i - 1) | info | i) */
        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(hmac, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(hmac, info, info_len))
            goto err;

        if (!HMAC_Update(hmac, &ctr, 1))
            goto err;

        if (!HMAC_Final(hmac, prev, NULL))
            goto err;

        copy_len = (dig_len > okm_len - done_len) ? okm_len - done_len : dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = 1;

err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    return ret;
}

/*
 * TLS uses slight variations of the above and for FIPS validation purposes,
 * they need to be present here.
 * Refer to RFC 8446 section 7 for specific details.
 */

/*
 * Given a |secret|; a |label| of length |labellen|; and |data| of length
 * |datalen| (e.g. typically a hash of the handshake messages), derive a new
 * secret |outlen| bytes long and store it in the location pointed to be |out|.
 * The |data| value may be zero length. Returns 1 on success and 0 on failure.
 */
static int prov_tls13_hkdf_expand(const EVP_MD *md,
    const unsigned char *key, size_t keylen,
    const unsigned char *prefix, size_t prefixlen,
    const unsigned char *label, size_t labellen,
    const unsigned char *data, size_t datalen,
    unsigned char *out, size_t outlen)
{
    size_t hkdflabellen;
    unsigned char hkdflabel[HKDF_MAXBUF];
    WPACKET pkt;

    /*
     * 2 bytes for length of derived secret + 1 byte for length of combined
     * prefix and label + bytes for the label itself + 1 byte length of hash
     * + bytes for the hash itself.  We've got the maximum the KDF can handle
     * which should always be sufficient.
     */
    if (!WPACKET_init_static_len(&pkt, hkdflabel, sizeof(hkdflabel), 0)
        || !WPACKET_put_bytes_u16(&pkt, outlen)
        || !WPACKET_start_sub_packet_u8(&pkt)
        || !WPACKET_memcpy(&pkt, prefix, prefixlen)
        || !WPACKET_memcpy(&pkt, label, labellen)
        || !WPACKET_close(&pkt)
        || !WPACKET_sub_memcpy_u8(&pkt, data, (data == NULL) ? 0 : datalen)
        || !WPACKET_get_total_written(&pkt, &hkdflabellen)
        || !WPACKET_finish(&pkt)) {
        WPACKET_cleanup(&pkt);
        return 0;
    }

    return HKDF_Expand(md, key, keylen, hkdflabel, hkdflabellen,
        out, outlen);
}

static int prov_tls13_hkdf_generate_secret(OSSL_LIB_CTX *libctx,
    const EVP_MD *md,
    const unsigned char *prevsecret,
    size_t prevsecretlen,
    const unsigned char *insecret,
    size_t insecretlen,
    const unsigned char *prefix,
    size_t prefixlen,
    const unsigned char *label,
    size_t labellen,
    unsigned char *out, size_t outlen)
{
    size_t mdlen;
    int ret;
    unsigned char preextractsec[EVP_MAX_MD_SIZE];
    /* Always filled with zeros */
    static const unsigned char default_zeros[EVP_MAX_MD_SIZE];

    ret = EVP_MD_get_size(md);
    /* Ensure cast to size_t is safe */
    if (ret <= 0)
        return 0;
    mdlen = (size_t)ret;

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = mdlen;
    } else {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        unsigned char hash[EVP_MAX_MD_SIZE];

        /* The pre-extract derive step uses a hash of no messages */
        if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
            EVP_MD_CTX_free(mctx);
            return 0;
        }
        EVP_MD_CTX_free(mctx);

        /* Generate the pre-extract secret */
        if (!prov_tls13_hkdf_expand(md, prevsecret, prevsecretlen,
                prefix, prefixlen, label, labellen,
                hash, mdlen, preextractsec, mdlen))
            return 0;
        prevsecret = preextractsec;
        prevsecretlen = mdlen;
    }

    ret = HKDF_Extract(libctx, md, prevsecret, prevsecretlen,
        insecret, insecretlen, out, outlen);

    if (prevsecret == preextractsec)
        OPENSSL_cleanse(preextractsec, mdlen);
    return ret;
}

#ifdef FIPS_MODULE
static int fips_tls1_3_digest_check_passed(KDF_HKDF *ctx, const EVP_MD *md)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(ctx->provctx);
    /*
     * Perform digest check
     *
     * According to RFC 8446 appendix B.4, the valid hash functions are
     * specified in FIPS 180-4. However, it only lists SHA2-256 and SHA2-384 in
     * the table. ACVP also only lists the same set of hash functions.
     */
    int digest_unapproved = !EVP_MD_is_a(md, SN_sha256)
        && !EVP_MD_is_a(md, SN_sha384);

    if (digest_unapproved) {
        if (!OSSL_FIPS_IND_ON_UNAPPROVED(ctx, OSSL_FIPS_IND_SETTABLE0,
                libctx, "TLS13 KDF", "Digest",
                FIPS_CONFIG_TLS13_KDF_DIGEST_CHECK)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
            return 0;
        }
    }
    return 1;
}

/*
 * Calculate the correct length of the secret key.
 *
 * RFC 8446:
 *   If a given secret is not available, then the 0-value consisting of a
 *   string of Hash.length bytes set to zeros is used.
 */
static size_t fips_tls1_3_key_size(KDF_HKDF *ctx)
{
    const EVP_MD *md = ossl_prov_digest_md(&ctx->digest);
    size_t key_size = 0;

    if (ctx->key != NULL)
        key_size = ctx->key_len;
    else if (md != NULL)
        key_size = EVP_MD_size(md);

    return key_size;
}

static int fips_tls1_3_key_check_passed(KDF_HKDF *ctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(ctx->provctx);
    int key_approved = ossl_kdf_check_key_size(fips_tls1_3_key_size(ctx));

    if (!key_approved) {
        if (!OSSL_FIPS_IND_ON_UNAPPROVED(ctx, OSSL_FIPS_IND_SETTABLE1,
                libctx, "TLS13 KDF", "Key size",
                FIPS_CONFIG_TLS13_KDF_KEY_CHECK)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    return 1;
}
#endif

static int kdf_tls1_3_derive(void *vctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;
    const EVP_MD *md;

    if (!ossl_prov_is_running() || !kdf_tls1_3_set_ctx_params(ctx, params))
        return 0;

    md = ossl_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    switch (ctx->mode) {
    default:
        return 0;

    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        return prov_tls13_hkdf_generate_secret(PROV_LIBCTX_OF(ctx->provctx),
            md,
            ctx->salt, ctx->salt_len,
            ctx->key, ctx->key_len,
            ctx->prefix, ctx->prefix_len,
            ctx->label, ctx->label_len,
            key, keylen);

    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        return prov_tls13_hkdf_expand(md, ctx->key, ctx->key_len,
            ctx->prefix, ctx->prefix_len,
            ctx->label, ctx->label_len,
            ctx->data, ctx->data_len,
            key, keylen);
    }
}

static int kdf_tls1_3_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct hkdf_all_set_ctx_params_st p;
    KDF_HKDF *ctx = vctx;

    if (ctx == NULL || !kdf_tls1_3_set_ctx_params_decoder(params, &p))
        return 0;

    if (!OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, OSSL_FIPS_IND_SETTABLE0, p.ind_d))
        return 0;
    if (!OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, OSSL_FIPS_IND_SETTABLE1, p.ind_k))
        return 0;

    if (!hkdf_common_set_ctx_params(ctx, &p))
        return 0;

    if (ctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        return 0;
    }

    if (p.prefix != NULL) {
        OPENSSL_free(ctx->prefix);
        ctx->prefix = NULL;
        if (!OSSL_PARAM_get_octet_string(p.prefix, (void **)&ctx->prefix, 0,
                &ctx->prefix_len))
            return 0;
    }

    if (p.label != NULL) {
        OPENSSL_free(ctx->label);
        ctx->label = NULL;
        if (!OSSL_PARAM_get_octet_string(p.label, (void **)&ctx->label, 0,
                &ctx->label_len))
            return 0;
    }

    if (p.data != NULL) {
        OPENSSL_clear_free(ctx->data, ctx->data_len);
        ctx->data = NULL;
        if (!OSSL_PARAM_get_octet_string(p.data, (void **)&ctx->data, 0,
                &ctx->data_len))
            return 0;
    }

#ifdef FIPS_MODULE
    if (p.digest != NULL) {
        const EVP_MD *md = ossl_prov_digest_md(&ctx->digest);

        if (!fips_tls1_3_digest_check_passed(ctx, md))
            return 0;
    }

    if (p.key != NULL)
        if (!fips_tls1_3_key_check_passed(ctx))
            return 0;
#endif

    if (p.cipher != NULL) {
        PROV_CIPHER pc = { 0 };
        const EVP_CIPHER *ciph;
        int clen;

        if (!ossl_prov_cipher_load(&pc, p.cipher, p.propq,
                PROV_LIBCTX_OF(ctx->provctx)))
            return 0;
        ciph = ossl_prov_cipher_cipher(&pc);
        clen = ciph != NULL ? EVP_CIPHER_get_key_length(ciph) : -1;
        if (clen <= 0) {
            ossl_prov_cipher_reset(&pc);
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        OPENSSL_free(ctx->multi_cipher_name);
        ctx->multi_cipher_name = OPENSSL_strdup(EVP_CIPHER_get0_name(ciph));
        ctx->multi_cipher_keylen = (size_t)clen;
        ossl_prov_cipher_reset(&pc);
        if (ctx->multi_cipher_name == NULL)
            return 0;
    }

    if (p.cipher_key_len != NULL
        && !OSSL_PARAM_get_size_t(p.cipher_key_len, &ctx->cipher_key_len))
        return 0;
    if (p.iv_len != NULL
        && !OSSL_PARAM_get_size_t(p.iv_len, &ctx->iv_len))
        return 0;

    return 1;
}

static const OSSL_PARAM *kdf_tls1_3_settable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return kdf_tls1_3_set_ctx_params_list;
}

static void kdf_tls1_3_multi_cleanup(KDF_HKDF *ctx)
{
    OPENSSL_clear_free(ctx->multi.key, ctx->multi.key_len);
    OPENSSL_free(ctx->multi.iv);
    OPENSSL_free(ctx->multi.cipher_key_type);
    memset(&ctx->multi, 0, sizeof(ctx->multi));
}

static int kdf_tls1_3_derive_multi(void *vctx, const OSSL_PARAM params[])
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;
    const EVP_MD *md;
    size_t cipher_key_len;

    if (!ossl_prov_is_running() || !kdf_tls1_3_set_ctx_params(ctx, params))
        return 0;

    md = ossl_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    /*
     * Settle on the cipher key length: the caller's, the named cipher's, or
     * an error if they disagree.  See the field comments in KDF_HKDF.
     */
    cipher_key_len = ctx->cipher_key_len;
    if (ctx->multi_cipher_keylen != 0) {
        if (cipher_key_len == 0) {
            cipher_key_len = ctx->multi_cipher_keylen;
        } else if (cipher_key_len != ctx->multi_cipher_keylen) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH,
                "%s needs a %zu byte key, not %zu", ctx->multi_cipher_name,
                ctx->multi_cipher_keylen, cipher_key_len);
            return 0;
        }
    }

    if (cipher_key_len == 0 && ctx->iv_len == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    /* Discard anything left by a previous derivation on this context */
    kdf_tls1_3_multi_cleanup(ctx);

    ctx->multi.cipher_key_type = OPENSSL_strdup(ossl_prov_cipher_skey_type(ctx->multi_cipher_name));
    if (ctx->multi.cipher_key_type == NULL)
        goto err;

    if (cipher_key_len > 0) {
        ctx->multi.key = OPENSSL_zalloc(cipher_key_len);
        if (ctx->multi.key == NULL)
            goto err;
        ctx->multi.key_len = cipher_key_len;

        if (!prov_tls13_hkdf_expand(md, ctx->key, ctx->key_len,
                ctx->prefix, ctx->prefix_len,
                (const unsigned char *)"key", 3,
                ctx->data, ctx->data_len,
                ctx->multi.key, ctx->multi.key_len))
            goto err;
    }

    if (ctx->iv_len > 0) {
        ctx->multi.iv = OPENSSL_zalloc(ctx->iv_len);
        if (ctx->multi.iv == NULL)
            goto err;
        ctx->multi.iv_len = ctx->iv_len;

        if (!prov_tls13_hkdf_expand(md, ctx->key, ctx->key_len,
                ctx->prefix, ctx->prefix_len,
                (const unsigned char *)"iv", 2,
                ctx->data, ctx->data_len,
                ctx->multi.iv, ctx->multi.iv_len))
            goto err;
    }

    return 1;

err:
    kdf_tls1_3_multi_cleanup(ctx);
    return 0;
}

static void *kdf_tls1_3_get_skey(void *vctx, const char *purpose,
    void *provctx, OSSL_FUNC_skeymgmt_import_fn *import)
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;
    OSSL_PARAM import_params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (ctx->multi.key == NULL
        || (strcmp(purpose, OSSL_KDF_PURPOSE_CLIENT_KEY) != 0
            && strcmp(purpose, OSSL_KDF_PURPOSE_SERVER_KEY) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return NULL;
    }

    import_params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SKEY_PARAM_RAW_BYTES, ctx->multi.key, ctx->multi.key_len);

    return import(provctx, OSSL_SKEYMGMT_SELECT_SECRET_KEY, import_params);
}

static int kdf_tls1_3_get_iv(void *vctx, const char *purpose,
    const unsigned char **pIV, size_t *pIVlen)
{
    KDF_HKDF *ctx = (KDF_HKDF *)vctx;

    if (ctx->multi.iv == NULL
        || (strcmp(purpose, OSSL_KDF_PURPOSE_CLIENT_IV) != 0
            && strcmp(purpose, OSSL_KDF_PURPOSE_SERVER_IV) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    *pIV = ctx->multi.iv;
    *pIVlen = ctx->multi.iv_len;
    return 1;
}

const OSSL_DISPATCH ossl_kdf_tls1_3_kdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))kdf_hkdf_new },
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void))kdf_hkdf_dup },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))kdf_hkdf_free },
    { OSSL_FUNC_KDF_RESET, (void (*)(void))kdf_hkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))kdf_tls1_3_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        (void (*)(void))kdf_tls1_3_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))kdf_tls1_3_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        (void (*)(void))hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))hkdf_common_get_ctx_params },
    { OSSL_FUNC_KDF_DERIVE_MULTI,
        (void (*)(void))kdf_tls1_3_derive_multi },
    { OSSL_FUNC_KDF_GET_SKEY,
        (void (*)(void))kdf_tls1_3_get_skey },
    { OSSL_FUNC_KDF_GET_IV,
        (void (*)(void))kdf_tls1_3_get_iv },
    OSSL_DISPATCH_END
};
