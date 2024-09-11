/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/thread.h"
#include "crypto/hss.h"

#if defined(OPENSSL_NO_DEFAULT_THREAD_POOL) && defined(OPENSSL_NO_THREAD_POOL)
# define LMS_NO_THREADS
#endif

#if !defined(OPENSSL_THREADS)
# define LMS_NO_THREADS
#endif

# define HSS_MIN_THREADS 1u
# define HSS_MAX_THREADS 8u

static OSSL_FUNC_signature_newctx_fn hss_newctx;
static OSSL_FUNC_signature_freectx_fn hss_freectx;
#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
static OSSL_FUNC_signature_sign_message_init_fn hss_sign_msg_init;
static OSSL_FUNC_signature_sign_message_update_fn hss_sign_msg_update;
static OSSL_FUNC_signature_sign_message_final_fn hss_sign_msg_final;
static OSSL_FUNC_signature_sign_fn hss_sign;
#endif
static OSSL_FUNC_signature_verify_message_init_fn hss_verify_msg_init;
static OSSL_FUNC_signature_verify_message_update_fn hss_verify_msg_update;
static OSSL_FUNC_signature_verify_message_final_fn hss_verify_msg_final;
static OSSL_FUNC_signature_verify_fn hss_verify;
static OSSL_FUNC_signature_set_ctx_params_fn hss_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn hss_settable_ctx_params;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    HSS_KEY *key;
    LMS_VALIDATE_CTX ctx;
#if !defined(LMS_NO_THREADS)
    LMS_VALIDATE_CTX *thread_data;
    void **threads;
    uint32_t next_thread;
#endif
    uint32_t max_threads;
    unsigned char *sig;
    size_t siglen;
    int operation;
    EVP_MD_CTX *mdctx;
} PROV_HSS_CTX;

static void *hss_newctx(void *provctx, const char *propq)
{
    PROV_HSS_CTX *ctx;
    LM_OTS_CTX *pubctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_HSS_CTX));
    if (ctx == NULL)
        return NULL;
    pubctx = ossl_lm_ots_ctx_new();
    if (pubctx == NULL)
        goto err;

    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL)
        goto err;
    ctx->max_threads = 1;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->ctx.pubctx = pubctx;
    return ctx;
err:
    ossl_lm_ots_ctx_free(pubctx);
    OPENSSL_free(ctx);
    return NULL;
}

static void hss_freectx(void *vctx)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    if (ctx == NULL)
        return;

    ossl_hss_key_free(ctx->key);
    OPENSSL_free(ctx->propq);
    ossl_lm_ots_ctx_free(ctx->ctx.pubctx);
    OPENSSL_free(ctx->sig);
    EVP_MD_free(ctx->ctx.md);
    EVP_MD_CTX_free(ctx->mdctx);

#if !defined(LMS_NO_THREADS)
    OPENSSL_free(ctx->threads);
    OPENSSL_free(ctx->thread_data);
#endif
    OPENSSL_free(ctx);
}

static int setdigest(PROV_HSS_CTX *ctx, const char *digestname)
{
    /*
     * Assume that only one digest can be used by LSS/HSS.
     * Set the digest to the one contained in the public key.
     * If the optional digestname passed in by the user is different
     * then return an error.
     */
    HSS_KEY *hsskey = ctx->key;
    LMS_KEY *key = sk_LMS_KEY_value(hsskey->lmskeys, 0);
    const char *pub_digestname = key->ots_params->digestname;

    if (ctx->ctx.md != NULL) {
        if (EVP_MD_is_a(ctx->ctx.md, pub_digestname))
            goto end;
        EVP_MD_free(ctx->ctx.md);
    }
    ctx->ctx.md = EVP_MD_fetch(ctx->libctx, pub_digestname, ctx->propq);
    if (ctx->ctx.md == NULL)
        return 0;
    ctx->mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->ctx.md, NULL))
        return 0;
end:
    return digestname == NULL || EVP_MD_is_a(ctx->ctx.md, digestname);
}

static int hss_sign_verify_init(void *vctx, void *key, const OSSL_PARAM params[],
                                const char *mdname, int operation)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;

    if (key == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (!ossl_hss_key_up_ref(key))
        return 0;
    ossl_hss_key_free(ctx->key);
    ctx->key = key;
    if (!setdigest(ctx, mdname))
        return 0;
    ctx->operation = operation;
    return hss_set_ctx_params(ctx, params);
}

#if !defined(LMS_NO_THREADS)
static int alloc_threads(PROV_HSS_CTX *ctx)
{
    if (ctx->threads != NULL || ctx->max_threads <= 1)
        return 1;
    ctx->threads = OPENSSL_zalloc(ctx->max_threads * sizeof(void *));
    if (ctx->threads == NULL)
        return 0;
    ctx->thread_data = OPENSSL_zalloc(ctx->max_threads * sizeof(LMS_VALIDATE_CTX));
    if (ctx->thread_data == NULL) {
        OPENSSL_free(ctx->threads);
        ctx->threads = NULL;
        return 0;
    }
    return 1;
}
#endif /* !defined(LMS_NO_THREADS) */

/* This is a single shot verify function */
static CRYPTO_THREAD_RETVAL verify_thread(void *ctx)
{
    LMS_VALIDATE_CTX *cur = (LMS_VALIDATE_CTX *)ctx;
    int ret;

    ret = ossl_lms_sig_verify_init(cur)
          && ossl_lms_sig_verify_update(cur, cur->msg, cur->msglen)
          && ossl_lms_sig_verify_final(cur);
    cur->failed = (ret != 1);
    return ret;
}

static int add_verify_job(PROV_HSS_CTX *ctx, LMS_SIG *lms_sig, LMS_KEY *key,
                          const unsigned char *msg, size_t msglen)
{
#if !defined(LMS_NO_THREADS)
    if (ctx->max_threads > 1) {
        uint32_t i;
        uint64_t avail = ossl_prov_get_avail_threads(ctx->libctx);
        void *thread;

        if (ctx->max_threads > avail) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_THREAD_POOL_SIZE,
                           "requested %u threads, available: %u",
                           ctx->max_threads, avail);
            return 0;
        }
        /* Multi threaded case */
        if (!alloc_threads(ctx))
            return 0;
        i = ctx->next_thread;
        thread = ctx->threads[i];
        if (ctx->thread_data[i].pubctx != NULL) {
            if (!ossl_prov_thread_join(thread, NULL)
                || !ossl_prov_thread_clean(thread))
                return 0;
            ossl_lm_ots_ctx_free(ctx->thread_data[i].pubctx);
            ctx->thread_data[i].pubctx = NULL;
            if (ctx->thread_data[i].failed)
                return 0;
        }
        ctx->thread_data[i].pub = key;
        ctx->thread_data[i].sig = lms_sig;
        ctx->thread_data[i].md = ctx->ctx.md;
        ctx->thread_data[i].pubctx = ossl_lm_ots_ctx_new();
        ctx->thread_data[i].msg = msg;
        ctx->thread_data[i].msglen = msglen;
        ctx->threads[i] = ossl_prov_thread_start(ctx->libctx, verify_thread,
                                                 &ctx->thread_data[i]);
        if (ctx->threads[i] == NULL) {
            ossl_lm_ots_ctx_free(ctx->thread_data[i].pubctx);
            ctx->thread_data[i].pubctx = NULL;
            return 0;
        }
        if (++ctx->next_thread >= ctx->max_threads)
            ctx->next_thread = 0;
        return 1;
    }
#endif /* !defined(LMS_NO_THREADS) */

    /* Single threaded case */
    ctx->ctx.sig = lms_sig;
    ctx->ctx.pub = key;
    ctx->ctx.msg = msg;
    ctx->ctx.msglen = msglen;
    return verify_thread(&ctx->ctx) == 1;
}

static int check_jobs(PROV_HSS_CTX *ctx)
{
#if !defined(LMS_NO_THREADS)
    uint32_t i, pass = 1;

    if (ctx->threads == NULL)
        return 1;
    for (i = 0; i < ctx->max_threads; ++i) {
        void *thread = ctx->threads[i];

        if (ctx->thread_data[i].pubctx != NULL) {
            ossl_prov_thread_join(thread, NULL);
            ossl_prov_thread_clean(thread);
            ossl_lm_ots_ctx_free(ctx->thread_data[i].pubctx);
            ctx->thread_data[i].pubctx = NULL;
        }
        if (ctx->thread_data[i].failed)
            pass = 0;
    }
    return pass;
#else
    return 1;
#endif
}

static int hss_sig_verify(PROV_HSS_CTX *ctx,
                          LMS_SIG *lms_sig,
                          LMS_KEY *key,
                          const unsigned char *msg, size_t msglen)
{
    if (msg == NULL) {
        LMS_VALIDATE_CTX *cur = &ctx->ctx;

        cur->pub = key;
        cur->sig = lms_sig;
        if (!ossl_lms_sig_verify_init(cur))
            return 0;
    } else {
        return add_verify_job(ctx, lms_sig, key, msg, msglen);
    }
    return 1;
}

static int hss_decoded(PROV_HSS_CTX *ctx)
{
    HSS_KEY *hsskey = ctx->key;
    return sk_LMS_SIG_num(hsskey->lmssigs) > 0;
}

static int hss_verify_int(PROV_HSS_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *msg, size_t msglen)
{
    int ret = 0, i;
    HSS_KEY *hsskey = ctx->key;

    /*
     * Decode the HSS signature data which contains signatures and public keys
     * This can just be a single level tree for the simple LMS case.
     */
    if (!ossl_hss_sig_decode(hsskey, sig, siglen))
        goto err;

    /* Verify each tree */
    for (i = 0; i < sk_LMS_SIG_num(hsskey->lmssigs) - 1; ++i) {
        LMS_KEY *next = sk_LMS_KEY_value(hsskey->lmskeys, i + 1);

        if (next == NULL)
            goto err;
        /*
         * As this call may create a thread to do the work it may not indicate
         * a verification failure until check_jobs() is called later
         */
        if (hss_sig_verify(ctx, sk_LMS_SIG_value(hsskey->lmssigs, i),
                           sk_LMS_KEY_value(hsskey->lmskeys, i),
                           next->pub.encoded, next->pub.encodedlen) != 1)
            goto err;
    }
    if (msg == NULL) {
        /*
         * If the msg is not passed in, the last verify will be done on the
         * main thread.
         */
        ctx->ctx.sig = sk_LMS_SIG_value(hsskey->lmssigs, i);
        ctx->ctx.pub = sk_LMS_KEY_value(hsskey->lmskeys, i);
        if (!ossl_lms_sig_verify_init(&ctx->ctx))
            goto err;
    } else {
        if (hss_sig_verify(ctx, sk_LMS_SIG_value(hsskey->lmssigs, i),
                           sk_LMS_KEY_value(hsskey->lmskeys, i),
                           msg, msglen) != 1)
            goto err;
    }
    ret = 1;
err:
    return ret;
}

/*
static int hss_digest_verify(void *vctx,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *msg, size_t msglen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    int ret = 0;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;
    ret = hss_verify_int(ctx, sig, siglen, msg, msglen);
    if (msg != NULL && !check_jobs(ctx))
        ret = 0;
    return ret;
}
*/

/*
static int hss_digest_verify_init(void *vctx, const char *mdname, void *key,
                                  const OSSL_PARAM params[])
{
    return hss_verify_init(vctx, key, params, mdname);
}
*/

#if 0
int hss_digest_verify_update(void *vctx,
                             const unsigned char *data, size_t datalen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
//    void *ptr;

//    if (ctx->pqmode
    return ossl_lms_sig_verify_update(&ctx->ctx, data, datalen);

    /* TODO - remove this caching part and return -1 */
    /*
     * Since the signature is required before we can process the message
     * we need to buffer the message, if we use the normal pattern of passing
     * the signature during the final.
     */
    ptr = OPENSSL_realloc(ctx->msg, ctx->msglen + datalen);
    if (ptr == NULL)
        return 0;

    ctx->msg = ptr;
    memcpy(&ctx->msg[ctx->msglen], data, datalen);
    ctx->msglen += datalen;
    return 1;
}
#endif

/*
int hss_digest_verify_final(void *vctx,
                            const unsigned char *sig, size_t siglen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    int ret = 0;

    if (ctx == NULL)
        return 0;
    return ossl_lms_sig_verify_final(&ctx->ctx);
}
*/

static int set_signature(PROV_HSS_CTX *ctx,
                         const unsigned char *sig, size_t siglen)
{
    if (siglen != ctx->siglen) {
        OPENSSL_free(ctx->sig);
        ctx->sig = NULL;
        ctx->siglen = 0;
        ctx->sig = OPENSSL_malloc(siglen);
        if (ctx->sig == NULL)
            return 0;
        ctx->siglen = siglen;
    }
    memcpy(ctx->sig, sig, siglen);
    return 1;
}

static int hss_verify(void *vctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *msg, size_t msglen)
{
    int ret = 0;
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    if (!set_signature(vctx, sig, siglen))
        goto err;
    if (!hss_verify_int(vctx, ctx->sig, ctx->siglen, msg, msglen))
        goto err;
    ret = 1;
err:
    if (!check_jobs(vctx))
        ret = 0;

    ossl_hss_key_verify_reset(ctx->key);
    return ret;
}

static int hss_verify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return hss_sign_verify_init(vctx, vkey, params, NULL, EVP_PKEY_OP_VERIFYMSG);
}

static int hss_verify_msg_update(void *vctx,
                                 const unsigned char *msg, size_t msglen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    if (ctx->sig == NULL)
        return 0;
    if (!hss_decoded(ctx)) {
        if (!hss_verify_int(ctx, ctx->sig, ctx->siglen, NULL, 0))
            return 0;
    }
    return ossl_lms_sig_verify_update(&ctx->ctx, msg, msglen);
}

static int hss_verify_msg_final(void *vctx)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    int ret = 0;

    ret = ossl_lms_sig_verify_final(&ctx->ctx);
    /* Wait for any jobs to finish */
    if (!check_jobs(ctx))
        ret = 0;
    ossl_hss_key_verify_reset(ctx->key);
    return ret;
}

/*
static int hss_digest_verify_pq_init(void *vctx, const char *mdname, void *key,
                                     const OSSL_PARAM params[],
                                     const unsigned char *sig, size_t siglen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    if (!hss_verify_init(vctx, key, params, mdname))
        return 0;
    ctx->pqmode = 1;
    return hss_digest_verify(vctx, sig, siglen, NULL, 0);
}

static int hss_digest_verify_pq_final(void *vctx)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    int ret = 0;

    if (!ctx->pqmode)
        return 0;
    ret = ossl_lms_sig_verify_final(&ctx->ctx);
    if (!check_jobs(ctx))
        ret = 0;
    return ret;
}
*/

static int hss_ctx_set_threads(PROV_HSS_CTX *ctx, uint32_t threads)
{
    if (threads > HSS_MAX_THREADS) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER,
                       "max threads: %u", HSS_MAX_THREADS);
        return 0;
    }
    if (threads < HSS_MIN_THREADS) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER,
                       "min threads: %u", HSS_MIN_THREADS);
        return 0;
    }

    ctx->max_threads = threads;
    return 1;
}

static int hss_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    PROV_HSS_CTX *ctx;
    uint32_t u32_value;

    ctx = (PROV_HSS_CTX *)vctx;
    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;
    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_SIGNATURE_PARAM_THREADS)) != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!hss_ctx_set_threads(ctx, u32_value))
            return 0;
    }
    if (ctx->operation == EVP_PKEY_OP_VERIFYMSG) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
        if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING) {
            if (!set_signature(ctx, p->data, p->data_size))
                return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_uint32(OSSL_SIGNATURE_PARAM_THREADS, NULL),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hss_settable_ctx_params(void *vctx,
                                                 ossl_unused void *provctx)
{
    return settable_ctx_params;
}

/*
static int hss_sign_init(void *vctx, const char *mdname,
                         void *vkey, const OSSL_PARAM params[])
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    return hss_sign_verify_init(vctx, vkey, params, mdname)
           && ossl_hss_sign_init(ctx->key);
}

static int hss_digest_sign(void *vctx, unsigned char *sigout,
                           size_t *siglen, size_t sigsize,
                           const unsigned char *tbs, size_t tbslen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    return ossl_hss_sign(ctx->key, tbs, tbslen, sigout, siglen, sigsize);
}
*/

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
static int hss_sign_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    return hss_sign_verify_init(vctx, vkey, params, NULL, EVP_PKEY_OP_SIGNMSG)
           && ossl_hss_sign_init(ctx->key);
}

static int hss_sign_msg_update(void *vctx,
                               const unsigned char *data, size_t datalen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    return ossl_hss_sign_update(ctx->key, data, datalen);
}

static int hss_sign_msg_final(void *vctx,
                              unsigned char *sig, size_t *siglen, size_t sigsz)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    return ossl_hss_sign_final(ctx->key, sig, siglen, sigsz);
}

static int hss_sign(void *vctx,
                    unsigned char *sig, size_t *siglen, size_t sigsz,
                    const unsigned char *msg, size_t msglen)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    HSS_KEY *hsskey = ctx->key;

    if (sig == NULL)
        return ossl_hss_sign_final(hsskey, sig, siglen, sigsz);
    return ossl_hss_sign_update(hsskey, msg, msglen)
           && ossl_hss_sign_final(hsskey, sig, siglen, sigsz);
}
#endif

const OSSL_DISPATCH ossl_hss_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))hss_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))hss_freectx },
#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (void (*)(void))hss_sign_msg_init },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
      (void (*)(void))hss_sign_msg_update },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
      (void (*)(void))hss_sign_msg_final },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))hss_sign },
#endif
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
      (void (*)(void))hss_verify_msg_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
        (void (*)(void))hss_verify_msg_update },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
      (void (*)(void))hss_verify_msg_final },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))hss_verify },
/*
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))hss_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))hss_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))hss_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))hss_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))hss_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))hss_digest_verify },
*/
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))hss_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))hss_settable_ctx_params },

    OSSL_DISPATCH_END
};
