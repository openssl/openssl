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
    { OSSL_DIGEST_PARAM_SSL3_MS, OSSL_PARAM_OCTET_STRING, NULL, 0, 0 },
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
#define SHA256MAGIC_LEN (sizeof(sha256magic) - 1)
#define SHA256_SERIALIZATION_LEN                      \
    (                                                 \
        SHA256MAGIC_LEN /* magic */                   \
        + sizeof(uint32_t) /* c->md_len */            \
        + sizeof(uint32_t) * 8 /* c->h */             \
        + sizeof(uint32_t) * 2 /* c->Nl + c->Nh */    \
        + sizeof(uint32_t) * SHA_LBLOCK /* c->data */ \
        + sizeof(uint32_t) /* c->num */               \
    )

static int SHA256_Serialize(SHA256_CTX *c, unsigned char *out,
    size_t *outlen)
{
    unsigned char *p;
    unsigned long i;

    if (out == NULL) {
        if (outlen == NULL)
            return 0;

        *outlen = SHA256_SERIALIZATION_LEN;
        return 1;
    }

    if (outlen != NULL && *outlen < SHA256_SERIALIZATION_LEN)
        return 0;

    p = out;

    /* Magic code */
    memcpy(p, sha256magic, SHA256MAGIC_LEN);
    p += SHA256MAGIC_LEN;

    /* md_len */
    p = OPENSSL_store_u32_le(p, c->md_len);

    /* h */
    for (i = 0; i < sizeof(c->h) / sizeof(SHA_LONG); i++)
        p = OPENSSL_store_u32_le(p, c->h[i]);

    /* Nl, Nh */
    p = OPENSSL_store_u32_le(p, c->Nl);
    p = OPENSSL_store_u32_le(p, c->Nh);

    /* data */
    for (i = 0; i < SHA_LBLOCK; i++)
        p = OPENSSL_store_u32_le(p, c->data[i]);

    /* num */
    p = OPENSSL_store_u32_le(p, c->num);

    if (outlen != NULL)
        *outlen = SHA256_SERIALIZATION_LEN;

    return 1;
}

static int SHA256_Deserialize(SHA256_CTX *c, const unsigned char *in,
    size_t inlen)
{
    const unsigned char *p;
    uint32_t val;
    unsigned long i;

    if (c == NULL || in == NULL || inlen != SHA256_SERIALIZATION_LEN)
        return 0;

    /* Magic code check */
    if (memcmp(in, sha256magic, SHA256MAGIC_LEN) != 0)
        return 0;

    p = in + SHA256MAGIC_LEN;

    /* md_len check */
    p = OPENSSL_load_u32_le(&val, p);
    if ((unsigned int)val != c->md_len) {
        return 0;
    }

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

    /* num */
    p = OPENSSL_load_u32_le(&val, p);
    c->num = (unsigned int)val;

    return 1;
}

static const unsigned char sha512magic[] = "SHA512v1";
#define SHA512MAGIC_LEN (sizeof(sha512magic) - 1)
#define SHA512_SERIALIZATION_LEN                   \
    (                                              \
        SHA512MAGIC_LEN /* magic */                \
        + sizeof(uint32_t) /* c->md_len */         \
        + sizeof(uint64_t) * 8 /* c->h */          \
        + sizeof(uint64_t) * 2 /* c->Nl + c->Nh */ \
        + SHA512_CBLOCK /* c->u.d/c->u.p */        \
        + sizeof(uint32_t) /* c->num */            \
    )

static int SHA512_Serialize(SHA512_CTX *c, unsigned char *out,
    size_t *outlen)
{
    unsigned char *p;
    unsigned long i;

    if (out == NULL) {
        if (outlen == NULL)
            return 0;

        *outlen = SHA512_SERIALIZATION_LEN;
        return 1;
    }

    if (outlen != NULL && *outlen < SHA512_SERIALIZATION_LEN)
        return 0;

    p = out;

    /* Magic code */
    memcpy(p, sha512magic, SHA512MAGIC_LEN);
    p += SHA512MAGIC_LEN;

    /* md_len */
    p = OPENSSL_store_u32_le(p, c->md_len);

    /* h */
    for (i = 0; i < sizeof(c->h) / sizeof(SHA_LONG64); i++)
        p = OPENSSL_store_u64_le(p, c->h[i]);

    /* Nl, Nh */
    p = OPENSSL_store_u64_le(p, c->Nl);
    p = OPENSSL_store_u64_le(p, c->Nh);

    /* data */
    memcpy(p, c->u.p, SHA512_CBLOCK);
    p += SHA512_CBLOCK;

    /* num */
    p = OPENSSL_store_u32_le(p, c->num);

    if (outlen != NULL)
        *outlen = SHA512_SERIALIZATION_LEN;

    return 1;
}

static int SHA512_Deserialize(SHA512_CTX *c, const unsigned char *in,
    size_t inlen)
{
    const unsigned char *p;
    uint32_t val32;
    uint64_t val;
    unsigned long i;

    if (c == NULL || in == NULL || inlen != SHA512_SERIALIZATION_LEN)
        return 0;

    /* Magic code */
    if (memcmp(in, sha512magic, SHA512MAGIC_LEN) != 0)
        return 0;

    p = in + SHA512MAGIC_LEN;

    /* md_len check */
    p = OPENSSL_load_u32_le(&val32, p);
    if ((unsigned int)val32 != c->md_len)
        return 0;

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

    /* num */
    p = OPENSSL_load_u32_le(&val32, p);
    c->num = (unsigned int)val32;

    return 1;
}

/* ossl_sha1_functions */
IMPLEMENT_digest_functions_with_settable_ctx(
    sha1, SHA_CTX, SHA_CBLOCK, SHA_DIGEST_LENGTH, SHA2_FLAGS,
    SHA1_Init, SHA1_Update, SHA1_Final,
    sha1_settable_ctx_params, sha1_set_ctx_params)

/* ossl_sha224_functions */
IMPLEMENT_digest_functions_with_serialize(sha224, SHA256_CTX,
    SHA256_CBLOCK, SHA224_DIGEST_LENGTH,
    SHA2_FLAGS, SHA224_Init,
    SHA224_Update, SHA224_Final,
    SHA256_Serialize, SHA256_Deserialize)

/* ossl_sha256_functions */
IMPLEMENT_digest_functions_with_serialize(sha256, SHA256_CTX,
    SHA256_CBLOCK, SHA256_DIGEST_LENGTH,
    SHA2_FLAGS, SHA256_Init,
    SHA256_Update, SHA256_Final,
    SHA256_Serialize, SHA256_Deserialize)
/* ossl_sha256_192_internal_functions */
IMPLEMENT_digest_functions_with_serialize(sha256_192_internal, SHA256_CTX,
    SHA256_CBLOCK, SHA256_192_DIGEST_LENGTH,
    SHA2_FLAGS, ossl_sha256_192_init,
    SHA256_Update, SHA256_Final,
    SHA256_Serialize, SHA256_Deserialize)
/* ossl_sha384_functions */
IMPLEMENT_digest_functions_with_serialize(sha384, SHA512_CTX,
    SHA512_CBLOCK, SHA384_DIGEST_LENGTH,
    SHA2_FLAGS, SHA384_Init,
    SHA384_Update, SHA384_Final,
    SHA512_Serialize, SHA512_Deserialize)

/* ossl_sha512_functions */
IMPLEMENT_digest_functions_with_serialize(sha512, SHA512_CTX,
    SHA512_CBLOCK, SHA512_DIGEST_LENGTH,
    SHA2_FLAGS, SHA512_Init,
    SHA512_Update, SHA512_Final,
    SHA512_Serialize, SHA512_Deserialize)

/* ossl_sha512_224_functions */
IMPLEMENT_digest_functions_with_serialize(sha512_224, SHA512_CTX,
    SHA512_CBLOCK, SHA224_DIGEST_LENGTH,
    SHA2_FLAGS, sha512_224_init,
    SHA512_Update, SHA512_Final,
    SHA512_Serialize, SHA512_Deserialize)

/* ossl_sha512_256_functions */
IMPLEMENT_digest_functions_with_serialize(sha512_256, SHA512_CTX,
    SHA512_CBLOCK, SHA256_DIGEST_LENGTH,
    SHA2_FLAGS, sha512_256_init,
    SHA512_Update, SHA512_Final,
    SHA512_Serialize, SHA512_Deserialize)
