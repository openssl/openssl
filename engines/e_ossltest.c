/*
 * Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * This is the OtlsTEST engine. It provides deliberately crippled digest
 * implementations for test purposes. It is highly insecure and must NOT be
 * used for any purpose except testing
 */

#include <stdio.h>
#include <string.h>

#include <opentls/engine.h>
#include <opentls/sha.h>
#include <opentls/md5.h>
#include <opentls/rsa.h>
#include <opentls/evp.h>
#include <opentls/modes.h>
#include <opentls/aes.h>
#include <opentls/rand.h>
#include <opentls/crypto.h>

#include "e_otlstest_err.c"

/* Engine Id and Name */
static const char *engine_otlstest_id = "otlstest";
static const char *engine_otlstest_name = "Opentls Test engine support";


/* Engine Lifetime functions */
static int otlstest_destroy(ENGINE *e);
static int otlstest_init(ENGINE *e);
static int otlstest_finish(ENGINE *e);
void ENGINE_load_otlstest(void);


/* Set up digests */
static int otlstest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);
static const RAND_METHOD *otlstest_rand_method(void);

/* MD5 */
static int digest_md5_init(EVP_MD_CTX *ctx);
static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_md5_md = NULL;
static const EVP_MD *digest_md5(void)
{
    if (_hidden_md5_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_md5, NID_md5WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, MD5_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, MD5_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(MD5_CTX))
            || !EVP_MD_meth_set_flags(md, 0)
            || !EVP_MD_meth_set_init(md, digest_md5_init)
            || !EVP_MD_meth_set_update(md, digest_md5_update)
            || !EVP_MD_meth_set_final(md, digest_md5_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_md5_md = md;
    }
    return _hidden_md5_md;
}

/* SHA1 */
static int digest_sha1_init(EVP_MD_CTX *ctx);
static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *digest_sha1(void)
{
    if (_hidden_sha1_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha1_init)
            || !EVP_MD_meth_set_update(md, digest_sha1_update)
            || !EVP_MD_meth_set_final(md, digest_sha1_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}

/* SHA256 */
static int digest_sha256_init(EVP_MD_CTX *ctx);
static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha256_md = NULL;
static const EVP_MD *digest_sha256(void)
{
    if (_hidden_sha256_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA256_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA256_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA256_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha256_init)
            || !EVP_MD_meth_set_update(md, digest_sha256_update)
            || !EVP_MD_meth_set_final(md, digest_sha256_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha256_md = md;
    }
    return _hidden_sha256_md;
}

/* SHA384/SHA512 */
static int digest_sha384_init(EVP_MD_CTX *ctx);
static int digest_sha512_init(EVP_MD_CTX *ctx);
static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha384_md = NULL;
static const EVP_MD *digest_sha384(void)
{
    if (_hidden_sha384_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha384, NID_sha384WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA384_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA512_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA512_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha384_init)
            || !EVP_MD_meth_set_update(md, digest_sha512_update)
            || !EVP_MD_meth_set_final(md, digest_sha384_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha384_md = md;
    }
    return _hidden_sha384_md;
}
static EVP_MD *_hidden_sha512_md = NULL;
static const EVP_MD *digest_sha512(void)
{
    if (_hidden_sha512_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha512, NID_sha512WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA512_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA512_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA512_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, digest_sha512_init)
            || !EVP_MD_meth_set_update(md, digest_sha512_update)
            || !EVP_MD_meth_set_final(md, digest_sha512_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha512_md = md;
    }
    return _hidden_sha512_md;
}
static void destroy_digests(void)
{
    EVP_MD_meth_free(_hidden_md5_md);
    _hidden_md5_md = NULL;
    EVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
    EVP_MD_meth_free(_hidden_sha256_md);
    _hidden_sha256_md = NULL;
    EVP_MD_meth_free(_hidden_sha384_md);
    _hidden_sha384_md = NULL;
    EVP_MD_meth_free(_hidden_sha512_md);
    _hidden_sha512_md = NULL;
}
static int otlstest_digest_nids(const int **nids)
{
    static int digest_nids[6] = { 0, 0, 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = digest_md5()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha1()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha256()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha384()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        if ((md = digest_sha512()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

/* Setup ciphers */
static int otlstest_ciphers(ENGINE *, const EVP_CIPHER **,
                            const int **, int);

static int otlstest_cipher_nids[] = {
    NID_aes_128_cbc, NID_aes_128_gcm, 0
};

/* AES128 */

int otlstest_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int otlstest_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
int otlstest_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int otlstest_aes128_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
static int otlstest_aes128_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr);

static EVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVP_CIPHER *otlstest_aes_128_cbc(void)
{
    if (_hidden_aes_128_cbc == NULL
        && ((_hidden_aes_128_cbc = EVP_CIPHER_meth_new(NID_aes_128_cbc,
                                                       16 /* block size */,
                                                       16 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc,
                                          EVP_CIPH_FLAG_DEFAULT_ASN1
                                          | EVP_CIPH_CBC_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc,
                                         otlstest_aes128_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc,
                                              otlstest_aes128_cbc_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc,
                                                  EVP_CIPHER_impl_ctx_size(EVP_aes_128_cbc())))) {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}
static EVP_CIPHER *_hidden_aes_128_gcm = NULL;

#define AES_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY |EVP_CIPH_FLAG_AEAD_CIPHER \
                | EVP_CIPH_GCM_MODE)

static const EVP_CIPHER *otlstest_aes_128_gcm(void)
{
    if (_hidden_aes_128_gcm == NULL
        && ((_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm,
                                                       1 /* block size */,
                                                       16 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm,
                                         otlstest_aes128_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm,
                                              otlstest_aes128_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm,
                                              otlstest_aes128_gcm_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm,
                              EVP_CIPHER_impl_ctx_size(EVP_aes_128_gcm())))) {
        EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

static void destroy_ciphers(void)
{
    EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
    EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
    _hidden_aes_128_cbc = NULL;
}

static int bind_otlstest(ENGINE *e)
{
    /* Ensure the otlstest error handling is set up */
    ERR_load_OtlsTEST_strings();

    if (!ENGINE_set_id(e, engine_otlstest_id)
        || !ENGINE_set_name(e, engine_otlstest_name)
        || !ENGINE_set_digests(e, otlstest_digests)
        || !ENGINE_set_ciphers(e, otlstest_ciphers)
        || !ENGINE_set_RAND(e, otlstest_rand_method())
        || !ENGINE_set_destroy_function(e, otlstest_destroy)
        || !ENGINE_set_init_function(e, otlstest_init)
        || !ENGINE_set_finish_function(e, otlstest_finish)) {
        OtlsTESTerr(OtlsTEST_F_BIND_OtlsTEST, OtlsTEST_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

#ifndef OPENtls_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_otlstest_id) != 0))
        return 0;
    if (!bind_otlstest(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static ENGINE *engine_otlstest(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_otlstest(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_otlstest(void)
{
    /* Copied from eng_[opentls|dyn].c */
    ENGINE *toadd = engine_otlstest();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


static int otlstest_init(ENGINE *e)
{
    return 1;
}


static int otlstest_finish(ENGINE *e)
{
    return 1;
}


static int otlstest_destroy(ENGINE *e)
{
    destroy_digests();
    destroy_ciphers();
    ERR_unload_OtlsTEST_strings();
    return 1;
}

static int otlstest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return otlstest_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_md5:
        *digest = digest_md5();
        break;
    case NID_sha1:
        *digest = digest_sha1();
        break;
    case NID_sha256:
        *digest = digest_sha256();
        break;
    case NID_sha384:
        *digest = digest_sha384();
        break;
    case NID_sha512:
        *digest = digest_sha512();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static int otlstest_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = otlstest_cipher_nids;
        return (sizeof(otlstest_cipher_nids) - 1)
               / sizeof(otlstest_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = otlstest_aes_128_cbc();
        break;
    case NID_aes_128_gcm:
        *cipher = otlstest_aes_128_gcm();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}

static void fill_known_data(unsigned char *md, unsigned int len)
{
    unsigned int i;

    for (i=0; i<len; i++) {
        md[i] = (unsigned char)(i & 0xff);
    }
}

/*
 * MD5 implementation. We go through the motions of doing MD5 by deferring to
 * the standard implementation. Then we overwrite the result with a will defined
 * value, so that all "MD5" digests using the test engine always end up with
 * the same value.
 */
#undef data
#define data(ctx) ((MD5_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_md5_init(EVP_MD_CTX *ctx)
{
    return MD5_Init(data(ctx));
}

static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    return MD5_Update(data(ctx), data, (size_t)count);
}

static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = MD5_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, MD5_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA1 implementation.
 */
#undef data
#define data(ctx) ((SHA_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_sha1_init(EVP_MD_CTX *ctx)
{
    return SHA1_Init(data(ctx));
}

static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count)
{
    return SHA1_Update(data(ctx), data, (size_t)count);
}

static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = SHA1_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA256 implementation.
 */
#undef data
#define data(ctx) ((SHA256_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_sha256_init(EVP_MD_CTX *ctx)
{
    return SHA256_Init(data(ctx));
}

static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return SHA256_Update(data(ctx), data, (size_t)count);
}

static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = SHA256_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA256_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA384/512 implementation.
 */
#undef data
#define data(ctx) ((SHA512_CTX *)EVP_MD_CTX_md_data(ctx))
static int digest_sha384_init(EVP_MD_CTX *ctx)
{
    return SHA384_Init(data(ctx));
}

static int digest_sha512_init(EVP_MD_CTX *ctx)
{
    return SHA512_Init(data(ctx));
}

static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return SHA512_Update(data(ctx), data, (size_t)count);
}

static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    /* Actually uses SHA512_Final! */
    ret = SHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA384_DIGEST_LENGTH);
    }
    return ret;
}

static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = SHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA512_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * AES128 Implementation
 */

int otlstest_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    return EVP_CIPHER_meth_get_init(EVP_aes_128_cbc()) (ctx, key, iv, enc);
}

int otlstest_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf;
    int ret;

    tmpbuf = OPENtls_malloc(inl);

    /* OPENtls_malloc will return NULL if inl == 0 */
    if (tmpbuf == NULL && inl > 0)
        return -1;

    /* Remember what we were asked to encrypt */
    if (tmpbuf != NULL)
        memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    ret = EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_cbc())(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    if (tmpbuf != NULL)
        memcpy(out, tmpbuf, inl);
    OPENtls_free(tmpbuf);

    return ret;
}

int otlstest_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    return EVP_CIPHER_meth_get_init(EVP_aes_128_gcm()) (ctx, key, iv, enc);
}


int otlstest_aes128_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf = OPENtls_malloc(inl);

    /* OPENtls_malloc will return NULL if inl == 0 */
    if (tmpbuf == NULL && inl > 0)
        return -1;

    /* Remember what we were asked to encrypt */
    if (tmpbuf != NULL)
        memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_gcm())(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    if (tmpbuf != NULL && out != NULL)
        memcpy(out, tmpbuf, inl);
    OPENtls_free(tmpbuf);

    return inl;
}

static int otlstest_aes128_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr)
{
    /* Pass the ctrl down */
    int ret = EVP_CIPHER_meth_get_ctrl(EVP_aes_128_gcm())(ctx, type, arg, ptr);

    if (ret <= 0)
        return ret;

    switch(type) {
    case EVP_CTRL_AEAD_GET_TAG:
        /* Always give the same tag */
        memset(ptr, 0, EVP_GCM_TLS_TAG_LEN);
        break;

    default:
        break;
    }

    return 1;
}

static int otlstest_rand_bytes(unsigned char *buf, int num)
{
    unsigned char val = 1;

    while (--num >= 0)
        *buf++ = val++;
    return 1;
}

static int otlstest_rand_status(void)
{
    return 1;
}

static const RAND_METHOD *otlstest_rand_method(void)
{

    static RAND_METHOD otlst_rand_meth = {
        NULL,
        otlstest_rand_bytes,
        NULL,
        NULL,
        otlstest_rand_bytes,
        otlstest_rand_status
    };

    return &otlst_rand_meth;
}
