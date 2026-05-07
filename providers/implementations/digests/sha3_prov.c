/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "internal/sha3.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "internal/common.h"
#include "providers/implementations/digests/sha3_prov.inc"

#define SHA3_FLAGS PROV_DIGEST_FLAG_ALGID_ABSENT
#define SHAKE_FLAGS (PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)
#define CSHAKE_KECCAK_FLAGS PROV_DIGEST_FLAG_XOF

/*
 * Forward declaration of any unique methods implemented here. This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_digest_newctx_fn sha3_224_newctx;
static OSSL_FUNC_digest_newctx_fn sha3_256_newctx;
static OSSL_FUNC_digest_newctx_fn sha3_384_newctx;
static OSSL_FUNC_digest_newctx_fn sha3_512_newctx;
static OSSL_FUNC_digest_newctx_fn keccak_224_newctx;
static OSSL_FUNC_digest_newctx_fn keccak_256_newctx;
static OSSL_FUNC_digest_newctx_fn keccak_384_newctx;
static OSSL_FUNC_digest_newctx_fn keccak_512_newctx;
static OSSL_FUNC_digest_newctx_fn shake_128_newctx;
static OSSL_FUNC_digest_newctx_fn shake_256_newctx;
static OSSL_FUNC_digest_newctx_fn cshake_keccak_128_newctx;
static OSSL_FUNC_digest_newctx_fn cshake_keccak_256_newctx;
static OSSL_FUNC_digest_get_params_fn sha3_224_get_params;
static OSSL_FUNC_digest_get_params_fn sha3_256_get_params;
static OSSL_FUNC_digest_get_params_fn sha3_384_get_params;
static OSSL_FUNC_digest_get_params_fn sha3_512_get_params;
static OSSL_FUNC_digest_get_params_fn shake_128_get_params;
static OSSL_FUNC_digest_get_params_fn shake_256_get_params;
static OSSL_FUNC_digest_get_params_fn cshake_keccak_128_get_params;
static OSSL_FUNC_digest_get_params_fn cshake_keccak_256_get_params;

#define keccak_224_get_params sha3_224_get_params
#define keccak_256_get_params sha3_256_get_params
#define keccak_384_get_params sha3_384_get_params
#define keccak_512_get_params sha3_512_get_params

static OSSL_FUNC_digest_init_fn keccak_init;
static OSSL_FUNC_digest_init_fn keccak_init_params;
static OSSL_FUNC_digest_update_fn keccak_update;
static OSSL_FUNC_digest_final_fn keccak_final;
static OSSL_FUNC_digest_freectx_fn keccak_freectx;
static OSSL_FUNC_digest_copyctx_fn keccak_copyctx;
static OSSL_FUNC_digest_dupctx_fn keccak_dupctx;
static OSSL_FUNC_digest_squeeze_fn shake_squeeze;

static OSSL_FUNC_digest_get_ctx_params_fn shake_get_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn shake_gettable_ctx_params;
static OSSL_FUNC_digest_set_ctx_params_fn shake_set_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn shake_settable_ctx_params;

static int keccak_init(void *vctx, ossl_unused const OSSL_PARAM params[])
{
    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    /* The newctx() handles most of the ctx fixed setup. */
    ossl_sha3_reset((KECCAK1600_CTX *)vctx);
    return 1;
}

static int keccak_init_params(void *vctx, const OSSL_PARAM params[])
{
    return keccak_init(vctx, NULL)
        && shake_set_ctx_params(vctx, params);
}

static int keccak_update(void *vctx, const unsigned char *inp, size_t len)
{
    return ossl_sha3_absorb((KECCAK1600_CTX *)vctx, inp, len);
}

static int keccak_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outlen)
{
    int ret = 1;
    KECCAK1600_CTX *ctx = vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    if (ossl_unlikely(ctx->md_size == SIZE_MAX)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
        return 0;
    }
    ret = ossl_sha3_final(ctx, out, ctx->md_size);
    *outl = ctx->md_size;
    return ret;
}

static int shake_squeeze(void *vctx, unsigned char *out, size_t *outl,
    size_t outlen)
{
    int ret = 1;
    KECCAK1600_CTX *ctx = vctx;

    if (!ossl_prov_is_running())
        return 0;
    if (ctx->meth.squeeze == NULL)
        return 0;
    if (outlen > 0)
        ret = ossl_sha3_squeeze(ctx, out, outlen);
    if (outl != NULL)
        *outl = outlen;
    return ret;
}

static void keccak_freectx(void *vctx)
{
    KECCAK1600_CTX *ctx = (KECCAK1600_CTX *)vctx;

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void keccak_copyctx(void *voutctx, void *vinctx)
{
    KECCAK1600_CTX *outctx = (KECCAK1600_CTX *)voutctx;
    KECCAK1600_CTX *inctx = (KECCAK1600_CTX *)vinctx;

    *outctx = *inctx;
}

static void *keccak_dupctx(void *ctx)
{
    KECCAK1600_CTX *in = (KECCAK1600_CTX *)ctx;
    KECCAK1600_CTX *ret = ossl_prov_is_running() ? OPENSSL_malloc(sizeof(*ret))
                                                 : NULL;

    if (ret != NULL)
        *ret = *in;
    return ret;
}

static const unsigned char keccakmagic[] = "KECCAKv1";
#define KECCAKMAGIC_LEN (sizeof(keccakmagic) - 1)
#define KECCAK_SERIALIZATION_LEN                                                     \
    (                                                                                \
        KECCAKMAGIC_LEN /* magic string */                                           \
        + sizeof(uint64_t) /* impl-ID */                                             \
        + sizeof(uint64_t) /* c->md_size */                                          \
        + (sizeof(uint64_t) * 4) /* c->block_size, c->bufsz, c->pad, c->xof_state */ \
        + (sizeof(uint64_t) * 5 * 5) /* c->A */                                      \
        + (KECCAK1600_WIDTH / 8 - 32) /* c->buf */                                   \
    )

static int KECCAK_Serialize(KECCAK1600_CTX *c, int impl_id,
    unsigned char *output, size_t *outlen)
{
    unsigned char *p;
    int i, j;

    if (output == NULL) {
        if (outlen == NULL)
            return 0;

        *outlen = KECCAK_SERIALIZATION_LEN;
        return 1;
    }

    if (outlen != NULL && *outlen < KECCAK_SERIALIZATION_LEN)
        return 0;

    p = output;

    /* Magic code */
    memcpy(p, keccakmagic, KECCAKMAGIC_LEN);
    p += KECCAKMAGIC_LEN;

    /* Additional check data */
    p = OPENSSL_store_u64_le(p, impl_id);
    p = OPENSSL_store_u64_le(p, c->md_size);

    p = OPENSSL_store_u64_le(p, c->block_size);
    p = OPENSSL_store_u64_le(p, c->bufsz);
    p = OPENSSL_store_u64_le(p, c->pad);
    p = OPENSSL_store_u64_le(p, c->xof_state);

    /* A matrix */
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++)
            p = OPENSSL_store_u64_le(p, c->A[i][j]);
    }

    if (outlen != NULL)
        *outlen = KECCAK_SERIALIZATION_LEN;

    /* buf */
    memcpy(p, c->buf, sizeof(c->buf));

    return 1;
}

/*
 * This function only performs basic input sanity checks and is not
 * built to handle malicious input data. Only trusted input should be
 * fed to this function
 */
static int KECCAK_Deserialize(KECCAK1600_CTX *c, int impl_id,
    const unsigned char *input, size_t len)
{
    const unsigned char *p;
    uint64_t val;
    int i, j;

    if (c == NULL || input == NULL || len != KECCAK_SERIALIZATION_LEN)
        return 0;

    /* Magic code */
    if (memcmp(input, keccakmagic, KECCAKMAGIC_LEN) != 0)
        return 0;

    p = input + KECCAKMAGIC_LEN;

    /* Check for matching Impl ID */
    p = OPENSSL_load_u64_le(&val, p);
    if (val != (uint64_t)impl_id)
        return 0;

    /* Check for matching md_size */
    p = OPENSSL_load_u64_le(&val, p);
    if (val != (uint64_t)c->md_size)
        return 0;

    /* check that block_size is congruent with the initialized value */
    p = OPENSSL_load_u64_le(&val, p);
    if (val != c->block_size)
        return 0;
    /* check that bufsz does not exceed block_size */
    p = OPENSSL_load_u64_le(&val, p);
    if (val > c->block_size)
        return 0;
    c->bufsz = (size_t)val;
    p = OPENSSL_load_u64_le(&val, p);
    if (val != c->pad)
        return 0;
    p = OPENSSL_load_u64_le(&val, p);
    c->xof_state = (int)val;

    /* A matrix */
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            p = OPENSSL_load_u64_le(&val, p);
            c->A[i][j] = val;
        }
    }

    /* buf */
    memcpy(c->buf, p, sizeof(c->buf));

    return 1;
}

#define IMPLEMENT_SERIALIZE_FNS(name, id)                              \
    static int name##_serialize(void *vctx, unsigned char *out,        \
        size_t *outlen)                                                \
    {                                                                  \
        return KECCAK_Serialize(vctx, id, out, outlen);                \
    }                                                                  \
    static int name##_deserialize(void *vctx, const unsigned char *in, \
        size_t inlen)                                                  \
    {                                                                  \
        return KECCAK_Deserialize(vctx, id, in, inlen);                \
    }

#define KECCAK_SER_ID 0x010000
#define SHAKE_SER_ID 0x020000
#define SHA3_SER_ID 0x040000
#define CSHAKE_KECCAK_SER_ID 0x080000

IMPLEMENT_SERIALIZE_FNS(sha3_224, SHA3_SER_ID + 224)
IMPLEMENT_SERIALIZE_FNS(sha3_256, SHA3_SER_ID + 256)
IMPLEMENT_SERIALIZE_FNS(sha3_384, SHA3_SER_ID + 384)
IMPLEMENT_SERIALIZE_FNS(sha3_512, SHA3_SER_ID + 512)
IMPLEMENT_SERIALIZE_FNS(keccak_224, KECCAK_SER_ID + 224)
IMPLEMENT_SERIALIZE_FNS(keccak_256, KECCAK_SER_ID + 256)
IMPLEMENT_SERIALIZE_FNS(keccak_384, KECCAK_SER_ID + 384)
IMPLEMENT_SERIALIZE_FNS(keccak_512, KECCAK_SER_ID + 512)
IMPLEMENT_SERIALIZE_FNS(shake_128, SHAKE_SER_ID + 128)
IMPLEMENT_SERIALIZE_FNS(shake_256, SHAKE_SER_ID + 256)
IMPLEMENT_SERIALIZE_FNS(cshake_keccak_128, CSHAKE_KECCAK_SER_ID + 128)
IMPLEMENT_SERIALIZE_FNS(cshake_keccak_256, CSHAKE_KECCAK_SER_ID + 256)

static const OSSL_PARAM *shake_gettable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return shake_get_ctx_params_list;
}

static int shake_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct shake_get_ctx_params_st p;
    KECCAK1600_CTX *ctx = (KECCAK1600_CTX *)vctx;

    if (ctx == NULL || !shake_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.xoflen != NULL && !OSSL_PARAM_set_size_t(p.xoflen, ctx->md_size)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    /* Size is an alias of xoflen but separate them for compatibility */
    if (p.size != NULL && !OSSL_PARAM_set_size_t(p.size, ctx->md_size)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *shake_settable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *provctx)
{
    return shake_set_ctx_params_list;
}

static int shake_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct shake_set_ctx_params_st p;
    KECCAK1600_CTX *ctx = (KECCAK1600_CTX *)vctx;

    if (ossl_unlikely(ctx == NULL || !shake_set_ctx_params_decoder(params, &p)))
        return 0;

    if (ossl_unlikely(p.xoflen != NULL
            && !OSSL_PARAM_get_size_t(p.xoflen, &ctx->md_size))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    return 1;
}

static void *sha3_224_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_sha3_new(224);
}
static void *sha3_256_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_sha3_new(256);
}
static void *sha3_384_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_sha3_new(384);
}
static void *sha3_512_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_sha3_new(512);
}
static void *keccak_224_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_keccak_new(224);
}
static void *keccak_256_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_keccak_new(256);
}
static void *keccak_384_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_keccak_new(384);
}
static void *keccak_512_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_keccak_new(512);
}
static void *shake_128_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_shake_new(128);
}
static void *shake_256_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_shake_new(256);
}

static void *cshake_keccak_128_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_cshake_keccak_new(128);
}
static void *cshake_keccak_256_newctx(void *provctx)
{
    DIGEST_PROV_CHECK(provctx, SHA3_256);
    return ossl_cshake_keccak_new(256);
}

static int sha3_224_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(224), SHA3_MDSIZE(224), SHA3_FLAGS);
}
static int sha3_256_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(256), SHA3_MDSIZE(256), SHA3_FLAGS);
}
static int sha3_384_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(384), SHA3_MDSIZE(384), SHA3_FLAGS);
}
static int sha3_512_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(512), SHA3_MDSIZE(512), SHA3_FLAGS);
}

static int shake_128_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(128), 0, SHAKE_FLAGS);
}
static int shake_256_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(256), 0, SHAKE_FLAGS);
}

static int cshake_keccak_128_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(128), CSHAKE_KECCAK_MDSIZE(128), CSHAKE_KECCAK_FLAGS);
}
static int cshake_keccak_256_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params,
        SHA3_BLOCKSIZE(256), CSHAKE_KECCAK_MDSIZE(256), CSHAKE_KECCAK_FLAGS);
}

#define OSSL_FPTR (void (*)(void))

/* ossl_sha3_224_functions */
const OSSL_DISPATCH ossl_sha3_224_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR sha3_224_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR sha3_224_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR sha3_224_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR sha3_224_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

/* ossl_sha3_256_functions */
const OSSL_DISPATCH ossl_sha3_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR sha3_256_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR sha3_256_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR sha3_256_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR sha3_256_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_sha3_384_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR sha3_384_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR sha3_384_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR sha3_384_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR sha3_384_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_sha3_512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR sha3_512_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR sha3_512_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR sha3_512_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR sha3_512_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_keccak_224_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR keccak_224_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR keccak_224_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR keccak_224_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR keccak_224_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_keccak_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR keccak_256_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR keccak_256_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR keccak_256_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR keccak_256_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_keccak_384_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR keccak_384_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR keccak_384_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR keccak_384_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR keccak_384_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_keccak_512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR keccak_512_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR keccak_512_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR keccak_512_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR keccak_512_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_shake_128_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR shake_128_newctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR shake_128_get_params },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR shake_128_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR shake_128_deserialize },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init_params },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FPTR shake_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FPTR shake_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, OSSL_FPTR shake_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, OSSL_FPTR shake_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, OSSL_FPTR shake_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_shake_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR shake_256_newctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR shake_256_get_params },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR shake_256_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR shake_256_deserialize },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init_params },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FPTR shake_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FPTR shake_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, OSSL_FPTR shake_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, OSSL_FPTR shake_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, OSSL_FPTR shake_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_cshake_keccak_128_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR cshake_keccak_128_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR cshake_keccak_128_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR cshake_keccak_128_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR cshake_keccak_128_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init_params },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FPTR shake_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FPTR shake_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, OSSL_FPTR shake_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, OSSL_FPTR shake_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, OSSL_FPTR shake_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_cshake_keccak_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, OSSL_FPTR cshake_keccak_256_newctx },
    { OSSL_FUNC_DIGEST_SERIALIZE, OSSL_FPTR cshake_keccak_256_serialize },
    { OSSL_FUNC_DIGEST_DESERIALIZE, OSSL_FPTR cshake_keccak_256_deserialize },
    { OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FPTR cshake_keccak_256_get_params },
    { OSSL_FUNC_DIGEST_INIT, OSSL_FPTR keccak_init_params },
    { OSSL_FUNC_DIGEST_UPDATE, OSSL_FPTR keccak_update },
    { OSSL_FUNC_DIGEST_FINAL, OSSL_FPTR keccak_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FPTR shake_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, OSSL_FPTR keccak_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, OSSL_FPTR keccak_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, OSSL_FPTR keccak_copyctx },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FPTR ossl_digest_default_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FPTR shake_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, OSSL_FPTR shake_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, OSSL_FPTR shake_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, OSSL_FPTR shake_gettable_ctx_params },
    { 0, NULL }
};
