/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/byteorder.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "crypto/sha.h"

#define SHA2_FLAGS PROV_DIGEST_FLAG_ALGID_ABSENT

static OSSL_FUNC_digest_set_ctx_params_fn sha1_set_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn sha1_settable_ctx_params;

static const OSSL_PARAM known_sha1_settable_ctx_params[] = {
    {OSSL_DIGEST_PARAM_SSL3_MS, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    OSSL_PARAM_END
};
static const OSSL_PARAM *sha1_settable_ctx_params(ossl_unused void *ctx,
                                                  ossl_unused void *provctx)
{
    return known_sha1_settable_ctx_params;
}

/* Special set_params method for SSL3 */
static int sha1_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    SHA_CTX *ctx = (SHA_CTX *)vctx;

    if (ctx == NULL)
        return 0;
    if (ossl_param_is_empty(params))
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS);
    if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING)
        return ossl_sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET,
                              (int)p->data_size, p->data);
    return 1;
}

static const unsigned char sha256magic[] = "SHA256v1";
#define SHA256_SERIALIZATION_LEN \
    ( \
     (sizeof(sha256magic) - 1) /* magic */ \
     + sizeof(uint32_t) * 8 /* c->h */ \
     + sizeof(uint32_t) * 2 /* c->Nl + c->Nh */ \
     + sizeof(uint32_t) * SHA_LBLOCK /* c->data */ \
     + sizeof(uint32_t) * 2 /* c->num + c->md_len */ \
     )

static int SHA256_Serialize(SHA256_CTX *c, unsigned char *output,
                            size_t *outlen)
{
    unsigned char *p;
    unsigned long i;

    if (output == NULL) {
        if (outlen == NULL)
            return 0;

        *outlen = SHA256_SERIALIZATION_LEN;
        return 1;
    }

    if (outlen != NULL && *outlen < SHA256_SERIALIZATION_LEN)
        return 0;

    p = output;

    /* Magic code */
    memcpy(p, sha256magic, sizeof(sha256magic) - 1);
    p += sizeof(sha256magic) - 1;

    /* h */
    for (i = 0; i < sizeof(c->h) / sizeof(SHA_LONG); i++)
        p = OPENSSL_store_u32_le(p, c->h[i]);

    /* Nl, Nh */
    p = OPENSSL_store_u32_le(p, c->Nl);
    p = OPENSSL_store_u32_le(p, c->Nh);

    /* data */
    for (i = 0; i < SHA_LBLOCK; i++)
        p = OPENSSL_store_u32_le(p, c->data[i]);

    /* num, md_len */
    p = OPENSSL_store_u32_le(p, c->num);
    p = OPENSSL_store_u32_le(p, c->md_len);

    if (outlen != NULL)
        *outlen = SHA256_SERIALIZATION_LEN;

    return 1;
}

static int SHA256_Deserialize(SHA256_CTX *c, const unsigned char *input,
                              size_t len, unsigned int md_len)
{
    const unsigned char *p;
    uint32_t val;
    unsigned long i;

    if (c == NULL || input == NULL || len != SHA256_SERIALIZATION_LEN)
        return 0;

    /* Magic code */
    if (memcmp(input, sha256magic, sizeof(sha256magic) - 1) != 0)
        return 0;

    p = input + sizeof(sha256magic) - 1;

    /* h */
    for (i = 0; i < (sizeof(c->h) / sizeof(SHA_LONG)); i++) {
        p = OPENSSL_load_u32_le(&val, p);
        c->h[i] = (SHA_LONG)val;
    }

    /* Nl, Nh */
    p = OPENSSL_load_u32_le(&val, p);
    c->Nl = (SHA_LONG)val;
    p = OPENSSL_load_u32_le(&val, p);
    c->Nh = (SHA_LONG)val;

    /* data */
    for (i = 0; i < SHA_LBLOCK; i++) {
        p = OPENSSL_load_u32_le(&val, p);
        c->data[i] = (SHA_LONG)val;
    }

    /* num, md_len */
    p = OPENSSL_load_u32_le(&val, p);
    c->num = (unsigned int)val;
    p = OPENSSL_load_u32_le(&val, p);
    c->md_len = (unsigned int)val;

    if (c->md_len != md_len) {
        OPENSSL_cleanse(c, sizeof(c));
        return 0;
    }

    return 1;
}

static const unsigned char sha512magic[] = "SHA512v1";
#define SHA512_SERIALIZATION_LEN \
    ( \
     (sizeof(sha512magic) - 1) /* magic */ \
     + sizeof(uint64_t) * 8 /* c->h */ \
     + sizeof(uint64_t) * 2 /* c->Nl + c->Nh */ \
     + SHA512_CBLOCK /* c->u.d/c->u.p */ \
     + sizeof(uint64_t) * 2 /* c->num + c->md_len */ \
     )

static int SHA512_Serialize(SHA512_CTX *c, unsigned char *output,
                            size_t *outlen)
{
    unsigned char *p;
    unsigned long i;

    if (output == NULL) {
        if (outlen == NULL)
            return 0;

        *outlen = SHA512_SERIALIZATION_LEN;
        return 1;
    }

    if (outlen != NULL && *outlen < SHA512_SERIALIZATION_LEN)
        return 0;

    p = output;

    /* Magic code */
    memcpy(p, sha512magic, sizeof(sha512magic) - 1);
    p += sizeof(sha512magic) - 1;

    /* h */
    for (i = 0; i < sizeof(c->h) / sizeof(SHA_LONG64); i++)
        p = OPENSSL_store_u64_le(p, c->h[i]);

    /* Nl, Nh */
    p = OPENSSL_store_u64_le(p, c->Nl);
    p = OPENSSL_store_u64_le(p, c->Nh);

    /* data */
    memcpy(p, c->u.p, SHA512_CBLOCK);
    p += SHA512_CBLOCK;

    /* num, md_len */
    p = OPENSSL_store_u64_le(p, c->num);
    p = OPENSSL_store_u64_le(p, c->md_len);

    if (outlen != NULL)
        *outlen = SHA512_SERIALIZATION_LEN;

    return 1;
}

static int SHA512_Deserialize(SHA512_CTX *c, const unsigned char *input,
                              size_t len, unsigned int md_len)
{
    const unsigned char *p;
    uint64_t val;
    unsigned long i;

    if (c == NULL || input == NULL || len != SHA512_SERIALIZATION_LEN)
        return 0;

    /* Magic code */
    if (memcmp(input, sha512magic, sizeof(sha512magic) - 1) != 0)
        return 0;

    p = input + sizeof(sha512magic) - 1;

    /* h */
    for (i = 0; i < (sizeof(c->h) / sizeof(SHA_LONG64)); i++) {
        p = OPENSSL_load_u64_le(&val, p);
        c->h[i] = (SHA_LONG64)val;
    }

    /* Nl, Nh */
    p = OPENSSL_load_u64_le(&val, p);
    c->Nl = (SHA_LONG64)val;
    p = OPENSSL_load_u64_le(&val, p);
    c->Nh = (SHA_LONG64)val;

    /* data */
    memcpy(c->u.p, p, SHA512_CBLOCK);
    p += SHA512_CBLOCK;

    /* num, md_len */
    p = OPENSSL_load_u64_le(&val, p);
    c->num = (unsigned int)val;
    p = OPENSSL_load_u64_le(&val, p);
    c->md_len = (unsigned int)val;

    if (c->md_len != md_len) {
        OPENSSL_cleanse(c, sizeof(c));
        return 0;
    }

    return 1;
}

static OSSL_FUNC_digest_settable_ctx_params_fn sha2_settable_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn sha2_gettable_ctx_params;

static const OSSL_PARAM known_sha2_settable_ctx_params[] = {
    {OSSL_DIGEST_SERIALIZATION, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    OSSL_PARAM_END
};
static const OSSL_PARAM *sha2_settable_ctx_params(ossl_unused void *ctx,
                                                  ossl_unused void *provctx)
{
    return known_sha2_settable_ctx_params;
}

static const OSSL_PARAM known_sha2_gettable_ctx_params[] = {
    {OSSL_DIGEST_SERIALIZATION, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    OSSL_PARAM_END
};
static const OSSL_PARAM *sha2_gettable_ctx_params(ossl_unused void *ctx,
                                                  ossl_unused void *provctx)
{
    return known_sha2_gettable_ctx_params;
}

#define SHA2_IMPLEMENT_CTX_PARAMS(name, bits, size)                           \
    static OSSL_FUNC_digest_get_ctx_params_fn name##_get_ctx_params;          \
    static int name##_get_ctx_params(void *vctx, OSSL_PARAM params[])         \
    {                                                                         \
        OSSL_PARAM *p;                                                        \
                                                                              \
        if (vctx == NULL)                                                     \
            return 0;                                                         \
        if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_SERIALIZATION)) != NULL) { \
            size_t outlen;                                                    \
            int ret;                                                          \
                                                                              \
            if (p->data_type != OSSL_PARAM_OCTET_STRING)                      \
                return 0;                                                     \
            outlen = p->data_size;                                            \
            if ((ret = SHA##bits##_Serialize((SHA##bits##_CTX *)vctx, p->data,\
                                             &outlen)))                       \
                p->return_size = outlen;                                      \
            return ret;                                                       \
        }                                                                     \
        return 1;                                                             \
    }                                                                         \
    static OSSL_FUNC_digest_set_ctx_params_fn name##_set_ctx_params;          \
    static int name##_set_ctx_params(void *vctx, const OSSL_PARAM params[])   \
    {                                                                         \
        const OSSL_PARAM *p;                                                  \
                                                                              \
        if (vctx == NULL)                                                     \
            return 0;                                                         \
        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_SERIALIZATION);       \
        if (p != NULL) {                                                      \
            if (p->data_type != OSSL_PARAM_OCTET_STRING)                      \
                return 0;                                                     \
            return SHA##bits##_Deserialize((SHA##bits##_CTX *)vctx, p->data,  \
                                           p->data_size, size);               \
        }                                                                     \
        return 1;                                                             \
    }

SHA2_IMPLEMENT_CTX_PARAMS(SHA224, 256, SHA224_DIGEST_LENGTH)
SHA2_IMPLEMENT_CTX_PARAMS(SHA256, 256, SHA256_DIGEST_LENGTH)
SHA2_IMPLEMENT_CTX_PARAMS(SHA256_192, 256, SHA256_192_DIGEST_LENGTH)
SHA2_IMPLEMENT_CTX_PARAMS(SHA384, 512, SHA384_DIGEST_LENGTH)
SHA2_IMPLEMENT_CTX_PARAMS(SHA512, 512, SHA512_DIGEST_LENGTH)
SHA2_IMPLEMENT_CTX_PARAMS(SHA512_224, 512, SHA224_DIGEST_LENGTH)
SHA2_IMPLEMENT_CTX_PARAMS(SHA512_256, 512, SHA256_DIGEST_LENGTH)

/* ossl_sha1_functions */
IMPLEMENT_digest_functions_with_settable_ctx(
    sha1, SHA_CTX, SHA_CBLOCK, SHA_DIGEST_LENGTH, SHA2_FLAGS,
    SHA1_Init, SHA1_Update, SHA1_Final,
    sha1_settable_ctx_params, sha1_set_ctx_params)

/* ossl_sha224_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha224, SHA256_CTX,
                                           SHA256_CBLOCK, SHA224_DIGEST_LENGTH,
                                           SHA2_FLAGS, SHA224_Init,
                                           SHA224_Update, SHA224_Final,
                                           sha2_gettable_ctx_params,
                                           SHA224_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA224_set_ctx_params)

/* ossl_sha256_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha256, SHA256_CTX,
                                           SHA256_CBLOCK, SHA256_DIGEST_LENGTH,
                                           SHA2_FLAGS, SHA256_Init,
                                           SHA256_Update, SHA256_Final,
                                           sha2_gettable_ctx_params,
                                           SHA256_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA256_set_ctx_params)
/* ossl_sha256_192_internal_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha256_192_internal, SHA256_CTX,
                                           SHA256_CBLOCK, SHA256_192_DIGEST_LENGTH,
                                           SHA2_FLAGS, ossl_sha256_192_init,
                                           SHA256_Update, SHA256_Final,
                                           sha2_gettable_ctx_params,
                                           SHA256_192_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA256_192_set_ctx_params)
/* ossl_sha384_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha384, SHA512_CTX,
                                           SHA512_CBLOCK, SHA384_DIGEST_LENGTH,
                                           SHA2_FLAGS, SHA384_Init,
                                           SHA384_Update, SHA384_Final,
                                           sha2_gettable_ctx_params,
                                           SHA384_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA384_set_ctx_params)

/* ossl_sha512_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha512, SHA512_CTX,
                                           SHA512_CBLOCK, SHA512_DIGEST_LENGTH,
                                           SHA2_FLAGS, SHA512_Init,
                                           SHA512_Update, SHA512_Final,
                                           sha2_gettable_ctx_params,
                                           SHA512_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA512_set_ctx_params)

/* ossl_sha512_224_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha512_224, SHA512_CTX,
                                           SHA512_CBLOCK, SHA224_DIGEST_LENGTH,
                                           SHA2_FLAGS, sha512_224_init,
                                           SHA512_Update, SHA512_Final,
                                           sha2_gettable_ctx_params,
                                           SHA512_224_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA512_224_set_ctx_params)

/* ossl_sha512_256_functions */
IMPLEMENT_digest_functions_with_ctx_params(sha512_256, SHA512_CTX,
                                           SHA512_CBLOCK, SHA256_DIGEST_LENGTH,
                                           SHA2_FLAGS, sha512_256_init,
                                           SHA512_Update, SHA512_Final,
                                           sha2_gettable_ctx_params,
                                           SHA512_256_get_ctx_params,
                                           sha2_settable_ctx_params,
                                           SHA512_256_set_ctx_params)
