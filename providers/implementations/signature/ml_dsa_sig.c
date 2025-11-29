/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <assert.h>
#include <string.h> /* memset */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include <openssl/evp.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/der_ml_dsa.h"
#include "prov/der_digests.h"
#include "crypto/ml_dsa.h"
#include "internal/common.h"
#include "internal/packet.h"
#include "internal/sizes.h"

#define ml_dsa_set_ctx_params_st        ml_dsa_verifymsg_set_ctx_params_st
#define ml_dsa_set_ctx_params_decoder   ml_dsa_verifymsg_set_ctx_params_decoder
#define hash_ml_dsa_set_ctx_params_st      ml_dsa_verifymsg_set_ctx_params_st
#define hash_ml_dsa_set_ctx_params_decoder ml_dsa_verifymsg_set_ctx_params_decoder

#include "providers/implementations/signature/ml_dsa_sig.inc"

static OSSL_FUNC_signature_sign_message_init_fn ml_dsa_sign_msg_init;
static OSSL_FUNC_signature_sign_message_update_fn ml_dsa_signverify_msg_update;
static OSSL_FUNC_signature_sign_message_final_fn ml_dsa_sign_msg_final;
static OSSL_FUNC_signature_verify_message_init_fn ml_dsa_verify_msg_init;
static OSSL_FUNC_signature_verify_message_update_fn ml_dsa_signverify_msg_update;
static OSSL_FUNC_signature_verify_message_final_fn ml_dsa_verify_msg_final;
static OSSL_FUNC_signature_digest_sign_init_fn ml_dsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_fn ml_dsa_sign;
static OSSL_FUNC_signature_digest_verify_init_fn ml_dsa_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_fn ml_dsa_verify;
static OSSL_FUNC_signature_freectx_fn ml_dsa_freectx;
static OSSL_FUNC_signature_set_ctx_params_fn ml_dsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn ml_dsa_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_params_fn ml_dsa_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn ml_dsa_gettable_ctx_params;
static OSSL_FUNC_signature_dupctx_fn ml_dsa_dupctx;
static OSSL_FUNC_signature_sign_init_fn ml_dsa_sign_init;
static OSSL_FUNC_signature_verify_init_fn ml_dsa_verify_init;
static OSSL_FUNC_signature_sign_fn ml_dsa_sign;
static OSSL_FUNC_signature_verify_fn ml_dsa_verify;
static OSSL_FUNC_signature_query_key_types_fn hash_ml_dsa_44_sigalg_query_key_types;
static OSSL_FUNC_signature_query_key_types_fn hash_ml_dsa_65_sigalg_query_key_types;
static OSSL_FUNC_signature_query_key_types_fn hash_ml_dsa_87_sigalg_query_key_types;

#define ML_DSA_SIGINFO_PURE(n)                                                 \
static const ML_DSA_SIGINFO ml_dsa_##n##_siginfo = {                           \
    EVP_PKEY_ML_DSA_##n,                                                       \
    ossl_der_oid_id_ml_dsa_##n, sizeof(ossl_der_oid_id_ml_dsa_##n),            \
    NULL, 0, 0                                                                 \
}

#define ML_DSA_SIGINFO_HASH(n, dig, hashsz)                                    \
static const ML_DSA_SIGINFO hash_ml_dsa_##n##_##dig##_siginfo = {              \
    EVP_PKEY_ML_DSA_##n,                                                       \
    ossl_der_oid_id_hash_ml_dsa_##n##_with_##dig,                              \
    sizeof(ossl_der_oid_id_hash_ml_dsa_##n##_with_##dig),                      \
    ossl_der_oid_id_##dig, sizeof(ossl_der_oid_id_##dig), hashsz               \
}

#define ML_DSA_SIGINFO_HASH_NO_SIG_OID(n, dig, hashsz)                         \
static const ML_DSA_SIGINFO hash_ml_dsa_##n##_##dig##_siginfo = {              \
    EVP_PKEY_ML_DSA_##n,                                                       \
    NULL, 0,                                                                   \
    ossl_der_oid_id_##dig, sizeof(ossl_der_oid_id_##dig), hashsz               \
}

/* Constants that are defined per signature algorithm */
typedef struct ml_dsa_siginfo_st {
    int key_type;
    /* The signature OID, most prehash ones do not have an OID */
    const uint8_t *sigalg_oid;
    size_t sigalg_oid_len;
    /* Used by prehash for the hash algorithm, NULL for pure mode */
    const uint8_t *hash_oid;
    size_t hash_oid_len;
    size_t hashlen; /* blocksize of a hash, or 0 for pure mode */
} ML_DSA_SIGINFO;

typedef struct {
    ML_DSA_KEY *key;
    OSSL_LIB_CTX *libctx;
    const ML_DSA_SIGINFO *siginfo;
    uint8_t context_string[ML_DSA_MAX_CONTEXT_STRING_LEN];
    size_t context_string_len;
    uint8_t test_entropy[ML_DSA_ENTROPY_LEN];
    size_t test_entropy_len;
    int msg_encode;
    int deterministic;
    /* The Algorithm Identifier of the signature algorithm */
    uint8_t aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    size_t  aid_len;
    int mu;     /* Flag indicating we should begin from mu, not the message */

    int operation;
    EVP_MD_CTX *md_ctx; /* Ctx for msg_init/update/final interface */
    unsigned char *sig; /* Signature, for verification */
    size_t siglen;
} PROV_ML_DSA_CTX;

static void ml_dsa_freectx(void *vctx)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    EVP_MD_CTX_free(ctx->md_ctx);
    OPENSSL_cleanse(ctx->test_entropy, ctx->test_entropy_len);
    OPENSSL_free(ctx->sig);
    OPENSSL_free(ctx);
}

static void *ml_dsa_newctx(void *provctx, const ML_DSA_SIGINFO *inf,
                           const char *propq)
{
    PROV_ML_DSA_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_ML_DSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->msg_encode = ML_DSA_MESSAGE_ENCODE;
    ctx->siginfo = inf;
    return ctx;
}

static void *ml_dsa_dupctx(void *vctx)
{
    PROV_ML_DSA_CTX *srcctx = (PROV_ML_DSA_CTX *)vctx;
    PROV_ML_DSA_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    /*
     * Note that the ML_DSA_KEY is ref counted via EVP_PKEY so we can just copy
     * the key here.
     */
    dstctx = OPENSSL_memdup(srcctx, sizeof(*srcctx));

    if (dstctx == NULL)
        return NULL;
    dstctx->sig = NULL;
    dstctx->md_ctx = NULL;

    if (srcctx->sig != NULL) {
        dstctx->sig = OPENSSL_memdup(srcctx->sig, srcctx->siglen);
        if (dstctx->sig == NULL) {
            /*
             * Can't call ml_dsa_freectx() here, as it would free
             * md_ctx which has not been duplicated yet.
             */
            OPENSSL_free(dstctx);
            return NULL;
        }
    }

    if (srcctx->md_ctx != NULL) {
        dstctx->md_ctx = EVP_MD_CTX_dup(srcctx->md_ctx);
        if (dstctx->md_ctx == NULL) {
            ml_dsa_freectx(dstctx);
            return NULL;
        }
    }

    return dstctx;
}

static int set_alg_id_buffer(PROV_ML_DSA_CTX *ctx)
{
    int ret;
    WPACKET pkt;
    uint8_t *aid = NULL;

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    ctx->aid_len = 0;
    if (ctx->siginfo->sigalg_oid == NULL)
        return 1;
    ret = WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf));
    if (!ret)
        return 0;
    ret = ossl_DER_w_algorithmIdentifier_ML_DSA(&pkt, -1,
                                                ctx->siginfo->sigalg_oid,
                                                ctx->siginfo->sigalg_oid_len);
    if (ret && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);
    if (aid != NULL && ctx->aid_len != 0)
        memmove(ctx->aid_buf, aid, ctx->aid_len);
    return 1;
}

static int ml_dsa_signverify_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[], int operation)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    ML_DSA_KEY *key = vkey;

    if (!ossl_prov_is_running()
            || ctx == NULL)
        return 0;

    if (vkey == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (key != NULL)
        ctx->key = vkey;
    if (!ossl_ml_dsa_key_matches(ctx->key, ctx->siginfo->key_type))
        return 0;

    set_alg_id_buffer(ctx);
    ctx->mu = 0;
    ctx->operation = operation;

    return ml_dsa_set_ctx_params(ctx, params);
}

static int ml_dsa_sign_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_SIGNMSG);
}

static int ml_dsa_verify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_VERIFYMSG);
}

static int ml_dsa_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_SIGN);
}

static int ml_dsa_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_VERIFY);
}

static int ml_dsa_digest_signverify_init(void *vctx, const char *mdname,
                                         void *vkey,
                                         const OSSL_PARAM params[], int op)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "Explicit digest not supported for ML-DSA operations");
        return 0;
    }

    ctx->mu = 0;

    if (vkey == NULL && ctx->key != NULL)
        return ml_dsa_set_ctx_params(ctx, params);

    return ml_dsa_signverify_init(vctx, vkey, params, op);
}

static int ml_dsa_digest_sign_init(void *vctx, const char *mdname,
                                   void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_digest_signverify_init(vctx, mdname, vkey, params, EVP_PKEY_OP_SIGN);
}

static int ml_dsa_digest_verify_init(void *vctx, const char *mdname,
                                     void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_digest_signverify_init(vctx, mdname, vkey, params, EVP_PKEY_OP_VERIFY);
}

static int ml_dsa_signverify_msg_update(void *vctx,
                                        const unsigned char *data,
                                        size_t datalen)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->mu)
        return 0;

    if (ctx->md_ctx == NULL) {
        ctx->md_ctx = ossl_ml_dsa_mu_init(ctx->key, ctx->msg_encode,
                                          ctx->context_string,
                                          ctx->context_string_len, 0);
        if (ctx->md_ctx == NULL)
            return 0;
    }

    return ossl_ml_dsa_mu_update(ctx->md_ctx, data, datalen);
}

static int ml_dsa_sign_msg_final(void *vctx, unsigned char *sig,
                                 size_t *siglen, size_t sigsize)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    uint8_t rand_tmp[ML_DSA_ENTROPY_LEN], *rnd = NULL;
    uint8_t mu[ML_DSA_MU_BYTES];
    int ret = 0;

    if (ctx == NULL)
        return 0;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->md_ctx == NULL)
        return 0;

    if (sig != NULL) {
        if (ctx->test_entropy_len != 0) {
            rnd = ctx->test_entropy;
        } else {
            rnd = rand_tmp;

            if (ctx->deterministic == 1)
                memset(rnd, 0, sizeof(rand_tmp));
            else if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rand_tmp), 0) <= 0)
                return 0;
        }

        if (!ossl_ml_dsa_mu_finalize(ctx->md_ctx, mu, sizeof(mu)))
            return 0;
    }

    ret = ossl_ml_dsa_sign(ctx->key, 1, mu, sizeof(mu),
                           NULL, 0, NULL, 0,
                           rnd, sizeof(rand_tmp), 0, sig, siglen, sigsize);
    if (rnd != ctx->test_entropy)
        OPENSSL_cleanse(rand_tmp, sizeof(rand_tmp));
    return ret;
}

static int ml_dsa_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,
                       const uint8_t *msg, size_t msg_len)
{
    int ret = 0;
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    uint8_t rand_tmp[ML_DSA_ENTROPY_LEN], *rnd = NULL;

    if (!ossl_prov_is_running())
        return 0;
    /* For the prehash case the message input should match the hash blocksize */
    if (ctx->siginfo->hashlen != 0 && ctx->siginfo->hashlen != msg_len)
        return 0;
    if (sig != NULL) {
        if (ctx->test_entropy_len != 0) {
            rnd = ctx->test_entropy;
        } else {
            rnd = rand_tmp;

            if (ctx->deterministic == 1)
                memset(rnd, 0, sizeof(rand_tmp));
            else if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rand_tmp), 0) <= 0)
                return 0;
        }
    }
    ret = ossl_ml_dsa_sign(ctx->key, ctx->mu, msg, msg_len,
                           ctx->siginfo->hash_oid, ctx->siginfo->hash_oid_len,
                           ctx->context_string, ctx->context_string_len,
                           rnd, sizeof(rand_tmp), ctx->msg_encode,
                           sig, siglen, sigsize);
    if (rnd != ctx->test_entropy)
        OPENSSL_cleanse(rand_tmp, sizeof(rand_tmp));
    return ret;
}

static int ml_dsa_digest_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,
                              const uint8_t *tbs, size_t tbslen)
{
    return ml_dsa_sign(vctx, sig, siglen, sigsize, tbs, tbslen);
}

static int ml_dsa_verify_msg_final(void *vctx)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    uint8_t mu[ML_DSA_MU_BYTES];

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->md_ctx == NULL)
        return 0;

    if (!ossl_ml_dsa_mu_finalize(ctx->md_ctx, mu, sizeof(mu)))
        return 0;

    return ossl_ml_dsa_verify(ctx->key, 1, mu, sizeof(mu), NULL, 0, NULL, 0, 0,
                              ctx->sig, ctx->siglen);
}

static int ml_dsa_verify(void *vctx, const uint8_t *sig, size_t siglen,
                         const uint8_t *msg, size_t msg_len)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    if (!ossl_prov_is_running())
        return 0;
    /* For the prehash case the message input should match the hash blocksize */
    if (ctx->siginfo->hashlen != 0 && ctx->siginfo->hashlen != msg_len)
        return 0;
    return ossl_ml_dsa_verify(ctx->key, ctx->mu, msg, msg_len,
                              ctx->siginfo->hash_oid, ctx->siginfo->hash_oid_len,
                              ctx->context_string, ctx->context_string_len,
                              ctx->msg_encode, sig, siglen);
}
static int ml_dsa_digest_verify(void *vctx,
                                const uint8_t *sig, size_t siglen,
                                const uint8_t *tbs, size_t tbslen)
{
    return ml_dsa_verify(vctx, sig, siglen, tbs, tbslen);
}

/*
 * Only need the param list for the signing case.  The decoder and structure
 * are shared between the sign and verify cases.
 */

static int ml_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ML_DSA_CTX *pctx = (PROV_ML_DSA_CTX *)vctx;
    struct ml_dsa_verifymsg_set_ctx_params_st p;

    if (pctx == NULL || !ml_dsa_verifymsg_set_ctx_params_decoder(params, &p))
        return 0;

    if (p.ctx != NULL) {
        void *vp = pctx->context_string;

        if (!OSSL_PARAM_get_octet_string(p.ctx, &vp, sizeof(pctx->context_string),
                                         &(pctx->context_string_len))) {
            pctx->context_string_len = 0;
            return 0;
        }
    }

    if (p.ent != NULL) {
        void *vp = pctx->test_entropy;

        pctx->test_entropy_len = 0;
        if (!OSSL_PARAM_get_octet_string(p.ent, &vp, sizeof(pctx->test_entropy),
                                         &(pctx->test_entropy_len)))
                return 0;
        if (pctx->test_entropy_len != sizeof(pctx->test_entropy)) {
            pctx->test_entropy_len = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            return 0;
        }
    }

    if (p.det != NULL && !OSSL_PARAM_get_int(p.det, &pctx->deterministic))
        return 0;

    /* The following parameters are skipped for HASHML-DSA signatures */
    if (pctx->siginfo->hashlen == 0) {
        if (p.msgenc != NULL && !OSSL_PARAM_get_int(p.msgenc, &pctx->msg_encode))
            return 0;

        if (p.mu != NULL && !OSSL_PARAM_get_int(p.mu, &pctx->mu))
            return 0;

        if (p.sig != NULL && pctx->operation == EVP_PKEY_OP_VERIFYMSG) {
            OPENSSL_free(pctx->sig);
            pctx->sig = NULL;
            pctx->siglen = 0;
            if (!OSSL_PARAM_get_octet_string(p.sig, (void **)&pctx->sig,
                                             0, &pctx->siglen))
                return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM *ml_dsa_settable_ctx_params(void *vctx,
                                                    ossl_unused void *provctx)
{
    PROV_ML_DSA_CTX *pctx = (PROV_ML_DSA_CTX *)vctx;

    if (pctx != NULL) {
        if (pctx->siginfo->hashlen != 0)
            return hash_ml_dsa_set_ctx_params_list;
        if (pctx->operation == EVP_PKEY_OP_VERIFYMSG)
            return ml_dsa_verifymsg_set_ctx_params_list;
    }
    return ml_dsa_set_ctx_params_list;
}

static const OSSL_PARAM *ml_dsa_gettable_ctx_params(ossl_unused void *vctx,
                                                    ossl_unused void *provctx)
{
    return ml_dsa_get_ctx_params_list;
}

static int ml_dsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    struct ml_dsa_get_ctx_params_st p;

    if (ctx == NULL || !ml_dsa_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.id != NULL
        && !OSSL_PARAM_set_octet_string(p.id,
                                        ctx->aid_len == 0 ? NULL : ctx->aid_buf,
                                        ctx->aid_len))
        return 0;

    return 1;
}

#define MAKE_SIGNATURE_FUNCTIONS(n)                                            \
    ML_DSA_SIGINFO_PURE(n);                                                    \
    static OSSL_FUNC_signature_newctx_fn ml_dsa_##n##_newctx;                  \
    static void *ml_dsa_##n##_newctx(void *provctx, const char *propq)         \
    {                                                                          \
        return ml_dsa_newctx(provctx, &ml_dsa_##n##_siginfo, propq);           \
    }                                                                          \
    const OSSL_DISPATCH ossl_ml_dsa_##n##_signature_functions[] = {            \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ml_dsa_##n##_newctx },   \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                               \
          (void (*)(void))ml_dsa_sign_msg_init },                              \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,                             \
          (void (*)(void))ml_dsa_signverify_msg_update },                      \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,                              \
          (void (*)(void))ml_dsa_sign_msg_final },                             \
        { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ml_dsa_sign },             \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                             \
          (void (*)(void))ml_dsa_verify_msg_init },                            \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,                           \
          (void (*)(void))ml_dsa_signverify_msg_update },                      \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,                            \
          (void (*)(void))ml_dsa_verify_msg_final },                           \
        { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ml_dsa_verify },         \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                \
          (void (*)(void))ml_dsa_digest_sign_init },                           \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,                                     \
          (void (*)(void))ml_dsa_sign },                                       \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                              \
          (void (*)(void))ml_dsa_digest_verify_init },                         \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,                                   \
          (void (*)(void))ml_dsa_verify },                                     \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ml_dsa_freectx },       \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                  \
          (void (*)(void))ml_dsa_set_ctx_params },                             \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                             \
          (void (*)(void))ml_dsa_settable_ctx_params },                        \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                  \
          (void (*)(void))ml_dsa_get_ctx_params },                             \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                             \
          (void (*)(void))ml_dsa_gettable_ctx_params },                        \
        { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ml_dsa_dupctx },         \
        OSSL_DISPATCH_END                                                      \
    }

/* Map HASHML-DSA signature names back to the ML-DSA key types */
static const char **hash_ml_dsa_44_sigalg_query_key_types(void)
{
    static const char *keytypes[] = { "ML-DSA-44", NULL };

    return keytypes;
}
static const char **hash_ml_dsa_65_sigalg_query_key_types(void)
{
    static const char *keytypes[] = { "ML-DSA-65", NULL };

    return keytypes;
}
static const char **hash_ml_dsa_87_sigalg_query_key_types(void)
{
    static const char *keytypes[] = { "ML-DSA-87", NULL };

    return keytypes;
}

#define MAKE_SIGNATURE_HASH_COMMON(n, dig)                                     \
static OSSL_FUNC_signature_newctx_fn hash_ml_dsa_##n##_##dig##_newctx;         \
static void *hash_ml_dsa_##n##_##dig##_newctx(void *provctx, const char *propq)\
{                                                                              \
    return ml_dsa_newctx(provctx, &hash_ml_dsa_##n##_##dig##_siginfo, propq);  \
}                                                                              \
const OSSL_DISPATCH ossl_hash_ml_dsa_##n##_##dig##_signature_functions[] = {   \
    { OSSL_FUNC_SIGNATURE_NEWCTX,                                              \
      (void (*)(void))hash_ml_dsa_##n##_##dig##_newctx },                      \
    { OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,                                     \
      (void (*)(void))hash_ml_dsa_##n##_sigalg_query_key_types },              \
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                           \
      (void (*)(void))ml_dsa_sign_init },                                      \
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                         \
      (void (*)(void))ml_dsa_verify_init },                                    \
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ml_dsa_sign },                 \
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ml_dsa_verify },             \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                    \
      (void (*)(void))ml_dsa_digest_sign_init },                               \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,                                         \
      (void (*)(void))ml_dsa_digest_sign },                                    \
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                                  \
      (void (*)(void))ml_dsa_digest_verify_init },                             \
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,                                       \
      (void (*)(void))ml_dsa_digest_verify },                                  \
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ml_dsa_freectx },           \
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                      \
      (void (*)(void))ml_dsa_get_ctx_params },                                 \
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                                 \
      (void (*)(void))ml_dsa_gettable_ctx_params },                            \
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                      \
      (void (*)(void))ml_dsa_set_ctx_params },                                 \
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                                 \
      (void (*)(void))ml_dsa_settable_ctx_params },                            \
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ml_dsa_dupctx },             \
    OSSL_DISPATCH_END                                                          \
}

#define MAKE_SIGNATURE_HASH(n, dig, hashsz)                                    \
    ML_DSA_SIGINFO_HASH(n, dig, hashsz);                                       \
    MAKE_SIGNATURE_HASH_COMMON(n, dig)

#define MAKE_SIGNATURE_HASH_NO_SIG_OID(n, dig, hashsz)                         \
    ML_DSA_SIGINFO_HASH_NO_SIG_OID(n, dig, hashsz);                            \
    MAKE_SIGNATURE_HASH_COMMON(n, dig)

MAKE_SIGNATURE_FUNCTIONS(44);
MAKE_SIGNATURE_FUNCTIONS(65);
MAKE_SIGNATURE_FUNCTIONS(87);
/*
 * Currently these are the only 3 HASH-ML-DSA algorithms with associated OIDS
 * (i.e. SHA512 only)
 * https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
 */
MAKE_SIGNATURE_HASH(44, sha512, 64);
MAKE_SIGNATURE_HASH(65, sha512, 64);
MAKE_SIGNATURE_HASH(87, sha512, 64);
MAKE_SIGNATURE_HASH_NO_SIG_OID(44, sha256, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(65, sha256, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(87, sha256, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(44, sha3_256, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(65, sha3_256, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(87, sha3_256, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(44, sha3_512, 64);
MAKE_SIGNATURE_HASH_NO_SIG_OID(65, sha3_512, 64);
MAKE_SIGNATURE_HASH_NO_SIG_OID(87, sha3_512, 64);
MAKE_SIGNATURE_HASH_NO_SIG_OID(44, shake128, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(65, shake128, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(87, shake128, 32);
MAKE_SIGNATURE_HASH_NO_SIG_OID(44, shake256, 64);
MAKE_SIGNATURE_HASH_NO_SIG_OID(65, shake256, 64);
MAKE_SIGNATURE_HASH_NO_SIG_OID(87, shake256, 64);
