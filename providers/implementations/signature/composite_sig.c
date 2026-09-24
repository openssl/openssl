/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/types.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/evp.h"
#include "crypto/ml_dsa.h"
#include "internal/der.h"
#include "internal/packet.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/composite.h"
#include "prov/names.h"

#define composite_set_ctx_params_st composite_verifymsg_set_ctx_params_st
#define composite_set_ctx_params_decoder composite_verifymsg_set_ctx_params_decoder
#include "providers/implementations/signature/composite_sig.inc"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

/*
 * Fixed 32-byte domain separation prefix per draft-ietf-lamps-pq-composite-sigs.
 * Byte encoding of the ASCII string "CompositeAlgorithmSignatures2025":
 *   436F6D706F73697465416C676F726974686D5369676E61747572657332303235
 */
static const uint8_t composite_sig_prefix[32] = {
    0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, /* Composit */ // codespell:ignore
    0x65, 0x41, 0x6C, 0x67, 0x6F, 0x72, 0x69, 0x74, /* eAlgorit */
    0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, /* hmSignat */
    0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35 /* ures2025 */
};

static OSSL_FUNC_signature_sign_fn composite_sign;

static void *composite_newctx(void *provctx, int evp_type, const char *propq)
{
    PROV_COMPOSITE_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_COMPOSITE_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

typedef enum {
    COMPOSITE_CLASSIC_RSA_PKCS15,
    COMPOSITE_CLASSIC_ECDSA
} COMPOSITE_CLASSIC_TYPE;

typedef struct {
    const char *name;
    const char *label; /* ASCII label for M' and ML-DSA ctx per draft §6 */
    const unsigned char *oid;
    size_t oid_sz;
    const char *prehash_alg; /* hash for composite PH(M) only */
    size_t prehash_len; /* prehash output length in bytes */
    const char *classic_hash; /* hash for traditional component signing (may differ
                               * from prehash_alg per draft-ietf-lamps-pq-composite-sigs §6);
                               * NULL for EdDSA (no digest arg needed) */
    COMPOSITE_CLASSIC_TYPE classic_type;
    int pss_salt_len; /* RSA-PSS only; 0 otherwise */
    const char *mgf1_hash; /* RSA-PSS MGF1 hash; NULL = same as classic_hash */
} COMPOSITE_ALG_INFO;

/*
 * prehash_alg: hash used for the composite PH(M) step.
 * classic_hash: hash used by the traditional component signature algorithm,
 *               which may differ from prehash_alg per draft-ietf-lamps-pq-composite-sigs §6;
 *               NULL for EdDSA variants (no digest argument).
 * mgf1_hash: RSA-PSS MGF1 hash override; NULL = same as classic_hash.
 */
static const COMPOSITE_ALG_INFO composite_alg_table[] = {
    /* name,  label,  oid, oid_sz,  prehash, phlen, classic_hash,
       classic_type, pss_salt_len, mgf1_hash */
    { "ML-DSA-65-RSA3072-PKCS15-SHA512", /* sha256WithRSAEncryption */
        "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
        ossl_der_oid_id_mldsa65_rsa3072_pkcs15_sha512,
        DER_OID_SZ_id_mldsa65_rsa3072_pkcs15_sha512,
        "SHA-512", 64, "SHA-256", COMPOSITE_CLASSIC_RSA_PKCS15, 0, NULL },
    { "ML-DSA-65-ECDSA-P256-SHA512", /* ecdsa-with-SHA256 */
        "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
        ossl_der_oid_id_mldsa65_ecdsa_p256_sha512,
        DER_OID_SZ_id_mldsa65_ecdsa_p256_sha512,
        "SHA-512", 64, "SHA-256", COMPOSITE_CLASSIC_ECDSA, 0, NULL },
};
#define COMPOSITE_NUM_ALGS \
    (sizeof(composite_alg_table) / sizeof(composite_alg_table[0]))

static const COMPOSITE_ALG_INFO *composite_find_alg_info(const char *name)
{
    size_t i;

    if (name == NULL)
        return NULL;
    for (i = 0; i < COMPOSITE_NUM_ALGS; i++) {
        if (OPENSSL_strcasecmp(name, composite_alg_table[i].name) == 0)
            return &composite_alg_table[i];
    }
    return NULL;
}

/*
 * Compute PH(M) for M' construction.  Handles both regular digests and the
 * SHAKE256 XOF used by ML-DSA-87-Ed448-SHAKE256.
 */
static int composite_compute_prehash(OSSL_LIB_CTX *libctx,
    const COMPOSITE_ALG_INFO *info,
    const uint8_t *msg, size_t msg_len,
    uint8_t *out)
{
    return EVP_Q_digest(libctx, info->prehash_alg, NULL, msg, msg_len, out, NULL);
}

/*
 * Build M' = Prefix(32) || Label || uint8(ctx_len) || ctx || PH(M) into a
 * newly allocated buffer, per draft-ietf-lamps-pq-composite-sigs §2.2.
 * Caller must OPENSSL_free() (or OPENSSL_clear_free()) the result.
 */
static uint8_t *composite_build_mprime(PROV_COMPOSITE_CTX *ctx,
    const COMPOSITE_ALG_INFO *info,
    const uint8_t *ph, size_t ph_len,
    size_t *tbs_len)
{
    uint8_t *tbs;
    size_t offset;

    if (ph_len != info->prehash_len)
        return NULL;

    *tbs_len = 32 + strlen(info->label) + 1 + ctx->context_string_len + info->prehash_len;
    tbs = OPENSSL_malloc(*tbs_len);
    if (tbs == NULL)
        return NULL;

    offset = 0;
    memcpy(tbs + offset, composite_sig_prefix, 32);
    offset += 32;
    memcpy(tbs + offset, info->label, strlen(info->label));
    offset += strlen(info->label);
    tbs[offset++] = (uint8_t)ctx->context_string_len;
    if (ctx->context_string_len > 0) {
        memcpy(tbs + offset, ctx->context_string, ctx->context_string_len);
        offset += ctx->context_string_len;
    }
    memcpy(tbs + offset, ph, info->prehash_len);
    return tbs;
}

/*
 * Sign tbs/tbs_len with the traditional (non-ML-DSA) component key.
 */
static int composite_classic_sign(PROV_COMPOSITE_CTX *ctx,
    const COMPOSITE_ALG_INFO *info,
    const uint8_t *tbs, size_t tbs_len,
    uint8_t *sig, size_t *siglen)
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (md_ctx == NULL)
        return 0;

    switch (info->classic_type) {
    case COMPOSITE_CLASSIC_ECDSA:
        if (!EVP_DigestSignInit_ex(md_ctx, NULL, info->classic_hash,
                ctx->libctx, NULL,
                ctx->key->classic_key, NULL))
            goto err;
        break;

    case COMPOSITE_CLASSIC_RSA_PKCS15:
        if (!EVP_DigestSignInit_ex(md_ctx, &pctx, info->classic_hash,
                ctx->libctx, NULL,
                ctx->key->classic_key, NULL))
            goto err;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
            goto err;
        break;

    default:
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        goto err;
    }

    if (!EVP_DigestSign(md_ctx, sig, siglen, tbs, tbs_len))
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

/*
 * Shared core of signing: given an already-computed PH(M) — whether from
 * hashing the whole message in one shot, from the streaming msg_update()/
 * msg_final() path, or supplied directly by the caller via
 * OSSL_SIGNATURE_PARAM_COMPOSITE_PREHASH — build M' and produce the
 * composite signature (ML-DSA component || classic component).
 */
static int composite_sign_ph(PROV_COMPOSITE_CTX *ctx,
    const COMPOSITE_ALG_INFO *info,
    uint8_t *sig, size_t *siglen, size_t sigsize,
    const uint8_t *ph, size_t ph_len)
{
    uint8_t *tbs = NULL;
    size_t tbs_len = 0;
    uint8_t rnd[32];
    size_t ml_dsa_siglen, classic_siglen, ml_dsa_sig_max;
    int ret = 0;

    ml_dsa_sig_max = ossl_ml_dsa_key_get_sig_len(ctx->key->ml_dsa_key);

    /*
     * Size query: upper bound only (EVP_PKEY_get_size() for EC is the max
     * DER size, not exact); real length is set after signing below.
     */
    if (sig == NULL) {
        *siglen = ml_dsa_sig_max
            + (size_t)EVP_PKEY_get_size(ctx->key->classic_key);
        return 1;
    }

    tbs = composite_build_mprime(ctx, info, ph, ph_len, &tbs_len);
    if (tbs == NULL)
        goto err;

    /* ML-DSA component: pure ML-DSA on M', with Label as mldsa_ctx per §3.1 */
    if (ctx->test_entropy_len != 0) {
        /* Fixed entropy for deterministic test vectors (non-PSS algorithms). */
        memcpy(rnd, ctx->test_entropy, sizeof(rnd));
    } else if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rnd), 0) <= 0) {
        goto err;
    }

    ml_dsa_siglen = ml_dsa_sig_max;
    if (!ossl_ml_dsa_sign(ctx->key->ml_dsa_key, 0,
            tbs, tbs_len,
            (const unsigned char *)info->label, strlen(info->label),
            rnd, sizeof(rnd), 1,
            sig, &ml_dsa_siglen, sigsize))
        goto err;

    /* Traditional component: sign M' with the classic key */
    classic_siglen = sigsize - ml_dsa_siglen;
    if (!composite_classic_sign(ctx, info, tbs, tbs_len,
            sig + ml_dsa_siglen, &classic_siglen))
        goto err;

    /* Wire format: mldsaSig || tradSig (flat concatenation) */
    *siglen = ml_dsa_siglen + classic_siglen;
    ret = 1;

err:
    OPENSSL_clear_free(tbs, tbs_len);
    return ret;
}

static int composite_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,
    const uint8_t *msg, size_t msg_len)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;
    uint8_t prehash[64]; /* max prehash output size */
    const uint8_t *ph = NULL;
    size_t ph_len = 0;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->key == NULL || ctx->alg == NULL)
        return 0;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    if (sig != NULL) {
        if (ctx->have_prehash) {
            /* Caller pre-computed PH(M) itself and passed it in as msg. */
            ph = msg;
            ph_len = msg_len;
        } else {
            if (!composite_compute_prehash(ctx->libctx, info, msg, msg_len, prehash))
                return 0;
            ph = prehash;
            ph_len = info->prehash_len;
        }
    }

    return composite_sign_ph(ctx, info, sig, siglen, sigsize, ph, ph_len);
}

static void composite_freectx(void *vctx)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;

    EVP_MD_CTX_free(ctx->prehash_ctx);
    OPENSSL_free(ctx->sig);
    OPENSSL_cleanse(ctx->test_entropy, sizeof(ctx->test_entropy));
    OPENSSL_free(ctx);
}

static void *composite_dupctx(void *vctx)
{
    PROV_COMPOSITE_CTX *src = (PROV_COMPOSITE_CTX *)vctx;
    PROV_COMPOSITE_CTX *dst;

    dst = OPENSSL_memdup(src, sizeof(*src));
    if (dst == NULL)
        return NULL;

    dst->prehash_ctx = NULL;
    dst->sig = NULL;

    if (src->prehash_ctx != NULL) {
        dst->prehash_ctx = EVP_MD_CTX_dup(src->prehash_ctx);
        if (dst->prehash_ctx == NULL)
            goto err;
    }

    if (src->sig != NULL) {
        dst->sig = OPENSSL_memdup(src->sig, src->siglen);
        if (dst->sig == NULL)
            goto err;
    }

    return dst;
err:
    EVP_MD_CTX_free(dst->prehash_ctx);
    OPENSSL_free(dst->sig);
    OPENSSL_free(dst);
    return NULL;
}

static int composite_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int composite_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;

    if (ctx == NULL || vkey == NULL)
        return 0;

    ctx->key = (COMPOSITE_KEY *)vkey;
    ctx->operation = EVP_PKEY_OP_SIGN;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    ctx->oid = info->oid;
    ctx->oid_sz = info->oid_sz;
    ctx->prehash_alg = info->prehash_alg;
    ctx->prehash_len = info->prehash_len;

    return composite_set_ctx_params(ctx, params);
}

static int composite_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;

    if (ctx == NULL || vkey == NULL)
        return 0;

    ctx->key = (COMPOSITE_KEY *)vkey;
    ctx->operation = EVP_PKEY_OP_VERIFY;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    ctx->oid = info->oid;
    ctx->oid_sz = info->oid_sz;
    ctx->prehash_alg = info->prehash_alg;
    ctx->prehash_len = info->prehash_len;

    return composite_set_ctx_params(ctx, params);
}

/*
 * Shared core of verification: mirrors composite_sign_ph(), taking an
 * already-computed PH(M) from any of the same three sources.
 */
static int composite_verify_ph(PROV_COMPOSITE_CTX *ctx,
    const COMPOSITE_ALG_INFO *info,
    const uint8_t *sig, size_t siglen,
    const uint8_t *ph, size_t ph_len)
{
    uint8_t *tbs = NULL;
    size_t tbs_len = 0;
    size_t ml_dsa_sig_len;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    ml_dsa_sig_len = ossl_ml_dsa_key_get_sig_len(ctx->key->ml_dsa_key);
    if (siglen <= ml_dsa_sig_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        return 0;
    }

    tbs = composite_build_mprime(ctx, info, ph, ph_len, &tbs_len);
    if (tbs == NULL)
        goto err;

    /* Verify ML-DSA component, with Label as mldsa_ctx per §3.2 */
    if (!ossl_ml_dsa_verify(ctx->key->ml_dsa_key, 0,
            tbs, tbs_len,
            (const unsigned char *)info->label, strlen(info->label),
            1, sig, ml_dsa_sig_len))
        goto err;

    /* Verify classic component */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    switch (info->classic_type) {
    case COMPOSITE_CLASSIC_ECDSA:
        if (!EVP_DigestVerifyInit_ex(md_ctx, NULL, info->classic_hash,
                ctx->libctx, NULL,
                ctx->key->classic_key, NULL))
            goto err;
        break;

    case COMPOSITE_CLASSIC_RSA_PKCS15:
        if (!EVP_DigestVerifyInit_ex(md_ctx, &pctx, info->classic_hash,
                ctx->libctx, NULL,
                ctx->key->classic_key, NULL))
            goto err;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
            goto err;
        break;

    default:
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        goto err;
    }

    if (EVP_DigestVerify(md_ctx,
            sig + ml_dsa_sig_len,
            siglen - ml_dsa_sig_len,
            tbs, tbs_len)
        != 1)
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_clear_free(tbs, tbs_len);
    return ret;
}

static int composite_verify(void *vctx, const uint8_t *sig, size_t siglen,
    const uint8_t *msg, size_t msg_len)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;
    uint8_t prehash[64]; /* max prehash output size */
    const uint8_t *ph;
    size_t ph_len;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->key == NULL || ctx->alg == NULL || sig == NULL || msg == NULL)
        return 0;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    if (ctx->have_prehash) {
        /* Caller pre-computed PH(M) itself and passed it in as msg. */
        ph = msg;
        ph_len = msg_len;
    } else {
        if (!composite_compute_prehash(ctx->libctx, info, msg, msg_len, prehash))
            return 0;
        ph = prehash;
        ph_len = info->prehash_len;
    }

    return composite_verify_ph(ctx, info, sig, siglen, ph, ph_len);
}

static const COMPOSITE_ALG_INFO *composite_ctx_alg_info(PROV_COMPOSITE_CTX *ctx)
{
    if (ctx == NULL || ctx->alg == NULL)
        return NULL;
    return composite_find_alg_info(ctx->alg);
}

/*
 * Start (idempotently) the streaming digest of the message for PH(M), using
 * the algorithm's prehash digest (e.g. SHA-512).  Called eagerly from the
 * *_MESSAGE_INIT() functions so that *_MESSAGE_FINAL() can hash an empty
 * message even if *_MESSAGE_UPDATE() is never called.
 */
static int composite_start_prehash(PROV_COMPOSITE_CTX *ctx)
{
    const COMPOSITE_ALG_INFO *info;
    EVP_MD *md;

    if (ctx->prehash_ctx != NULL)
        return 1;

    info = composite_ctx_alg_info(ctx);
    if (info == NULL)
        return 0;

    md = EVP_MD_fetch(ctx->libctx, info->prehash_alg, NULL);
    if (md == NULL)
        return 0;

    ctx->prehash_ctx = EVP_MD_CTX_new();
    if (ctx->prehash_ctx == NULL || !EVP_DigestInit_ex2(ctx->prehash_ctx, md, NULL)) {
        EVP_MD_CTX_free(ctx->prehash_ctx);
        ctx->prehash_ctx = NULL;
        EVP_MD_free(md);
        return 0;
    }
    EVP_MD_free(md);
    return 1;
}

static int composite_signverify_msg_update(void *vctx,
    const unsigned char *data,
    size_t datalen)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;

    if (ctx == NULL || !ossl_prov_is_running())
        return 0;

    if (!composite_start_prehash(ctx))
        return 0;

    return EVP_DigestUpdate(ctx->prehash_ctx, data, datalen);
}

static int composite_sign_msg_init(void *vctx, void *vkey,
    const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;

    return composite_sign_init(vctx, vkey, params)
        && composite_start_prehash(ctx);
}

static int composite_sign_msg_final(void *vctx, unsigned char *sig,
    size_t *siglen, size_t sigsize)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;
    uint8_t ph[64];
    unsigned int ph_len;

    if (ctx == NULL || !ossl_prov_is_running())
        return 0;

    info = composite_ctx_alg_info(ctx);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    if (sig == NULL)
        return composite_sign_ph(ctx, info, sig, siglen, sigsize, NULL, 0);

    if (ctx->prehash_ctx == NULL)
        return 0; /* msg_init() was never called */

    if (!EVP_DigestFinal_ex(ctx->prehash_ctx, ph, &ph_len))
        return 0;
    EVP_MD_CTX_free(ctx->prehash_ctx);
    ctx->prehash_ctx = NULL;

    return composite_sign_ph(ctx, info, sig, siglen, sigsize, ph, ph_len);
}

static int composite_verify_msg_init(void *vctx, void *vkey,
    const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;

    return composite_verify_init(vctx, vkey, params)
        && composite_start_prehash(ctx);
}

/*
 * Per provider-signature.pod, the signature to check is supplied out of
 * band via OSSL_SIGNATURE_PARAM_SIGNATURE (see composite_set_ctx_params()),
 * not as an argument here.
 */
static int composite_verify_msg_final(void *vctx)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;
    uint8_t ph[64];
    unsigned int ph_len;

    if (ctx == NULL || !ossl_prov_is_running())
        return 0;

    if (ctx->sig == NULL || ctx->prehash_ctx == NULL)
        return 0; /* msg_init() was never called, or no signature was set */

    info = composite_ctx_alg_info(ctx);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    if (!EVP_DigestFinal_ex(ctx->prehash_ctx, ph, &ph_len))
        return 0;
    EVP_MD_CTX_free(ctx->prehash_ctx);
    ctx->prehash_ctx = NULL;

    return composite_verify_ph(ctx, info, ctx->sig, ctx->siglen, ph, ph_len);
}

static int composite_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    struct composite_get_ctx_params_st p;

    if (ctx == NULL || !composite_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.id != NULL) {
        /* DER AlgorithmIdentifier = SEQUENCE { OID }, built like the other signature providers */
        WPACKET pkt;
        unsigned char aid_buf[32];
        unsigned char *aid;
        size_t aid_len;
        int ok;

        if (ctx->oid == NULL || ctx->oid_sz == 0)
            return 0;

        if (!WPACKET_init_der(&pkt, aid_buf, sizeof(aid_buf)))
            return 0;

        ok = ossl_DER_w_begin_sequence(&pkt, -1)
            && ossl_DER_w_precompiled(&pkt, -1, ctx->oid, ctx->oid_sz)
            && ossl_DER_w_end_sequence(&pkt, -1)
            && WPACKET_finish(&pkt);
        if (ok) {
            WPACKET_get_total_written(&pkt, &aid_len);
            aid = WPACKET_get_curr(&pkt);
            ok = OSSL_PARAM_set_octet_string(p.id, aid, aid_len);
        }
        WPACKET_cleanup(&pkt);
        if (!ok)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *composite_gettable_ctx_params(void *vctx, void *provctx)
{
    return composite_get_ctx_params_list;
}

static int composite_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    struct composite_verifymsg_set_ctx_params_st p;

    if (ctx == NULL || !composite_verifymsg_set_ctx_params_decoder(params, &p))
        return 0;

    if (p.ctx != NULL) {
        void *vp = ctx->context_string;

        if (!OSSL_PARAM_get_octet_string(p.ctx, &vp, sizeof(ctx->context_string),
                &ctx->context_string_len)) {
            ctx->context_string_len = 0;
            return 0;
        }
    }

    if (p.ent != NULL) {
        void *vp = ctx->test_entropy;

        ctx->test_entropy_len = 0;
        if (!OSSL_PARAM_get_octet_string(p.ent, &vp, sizeof(ctx->test_entropy),
                &ctx->test_entropy_len))
            return 0;
        if (ctx->test_entropy_len != sizeof(ctx->test_entropy)) {
            ctx->test_entropy_len = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            return 0;
        }
    }

    if (p.ph != NULL && !OSSL_PARAM_get_int(p.ph, &ctx->have_prehash))
        return 0;

    if (p.sig != NULL && ctx->operation == EVP_PKEY_OP_VERIFY) {
        OPENSSL_free(ctx->sig);
        ctx->sig = NULL;
        ctx->siglen = 0;
        if (!OSSL_PARAM_get_octet_string(p.sig, (void **)&ctx->sig, 0, &ctx->siglen))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *composite_settable_ctx_params(void *vctx, void *provctx)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;

    if (ctx != NULL && ctx->operation == EVP_PKEY_OP_VERIFY)
        return composite_verifymsg_set_ctx_params_list;
    return composite_set_ctx_params_list;
}

static int composite_digest_signverify_init(void *vctx, const char *mdname,
    void *vkey,
    const OSSL_PARAM params[])
{
    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
            "Explicit digest not supported for composite "
            "signature operations");
        return 0;
    }
    return composite_sign_init(vctx, vkey, params);
}

static int composite_digest_sign(void *vctx, uint8_t *sig, size_t *siglen,
    size_t sigsize, const uint8_t *tbs,
    size_t tbslen)
{
    return composite_sign(vctx, sig, siglen, sigsize, tbs, tbslen);
}

static int composite_digest_verify(void *vctx, const uint8_t *sig,
    size_t siglen, const uint8_t *tbs,
    size_t tbslen)
{
    return composite_verify(vctx, sig, siglen, tbs, tbslen);
}

/*
 * Per-algorithm newctx functions and dispatch tables.
 * The alg string is stored in the context for domain separator selection.
 */
#define MAKE_COMPOSITE_FUNCTIONS(name, namestr)                              \
    static void *composite_##name##_newctx(void *provctx, const char *propq) \
    {                                                                        \
        PROV_COMPOSITE_CTX *ctx = composite_newctx(provctx, 0, propq);       \
        if (ctx != NULL)                                                     \
            ctx->alg = namestr;                                              \
        return ctx;                                                          \
    }                                                                        \
    const OSSL_DISPATCH ossl_##name##_signature_functions[] = {              \
        { OSSL_FUNC_SIGNATURE_NEWCTX,                                        \
            (void (*)(void))composite_##name##_newctx },                     \
        { OSSL_FUNC_SIGNATURE_FREECTX,                                       \
            (void (*)(void))composite_freectx },                             \
        { OSSL_FUNC_SIGNATURE_DUPCTX,                                        \
            (void (*)(void))composite_dupctx },                              \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                     \
            (void (*)(void))composite_sign_init },                           \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                             \
            (void (*)(void))composite_sign_msg_init },                       \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,                           \
            (void (*)(void))composite_signverify_msg_update },               \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,                            \
            (void (*)(void))composite_sign_msg_final },                      \
        { OSSL_FUNC_SIGNATURE_SIGN,                                          \
            (void (*)(void))composite_sign },                                \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                   \
            (void (*)(void))composite_verify_init },                         \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                           \
            (void (*)(void))composite_verify_msg_init },                     \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,                         \
            (void (*)(void))composite_signverify_msg_update },               \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,                          \
            (void (*)(void))composite_verify_msg_final },                    \
        { OSSL_FUNC_SIGNATURE_VERIFY,                                        \
            (void (*)(void))composite_verify },                              \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                              \
            (void (*)(void))composite_digest_signverify_init },              \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,                                   \
            (void (*)(void))composite_digest_sign },                         \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                            \
            (void (*)(void))composite_digest_signverify_init },              \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,                                 \
            (void (*)(void))composite_digest_verify },                       \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                \
            (void (*)(void))composite_get_ctx_params },                      \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                           \
            (void (*)(void))composite_gettable_ctx_params },                 \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                \
            (void (*)(void))composite_set_ctx_params },                      \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                           \
            (void (*)(void))composite_settable_ctx_params },                 \
        OSSL_DISPATCH_END                                                    \
    }

MAKE_COMPOSITE_FUNCTIONS(mldsa65_rsa3072_pkcs15_sha512,
    "ML-DSA-65-RSA3072-PKCS15-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_ecdsa_p256_sha512,
    "ML-DSA-65-ECDSA-P256-SHA512");
