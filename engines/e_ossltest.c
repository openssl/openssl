/* engines/e_ossltest.c */
/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/*
 * This is the OSSLTEST engine. It provides deliberately crippled digest
 * implementations for test purposes. It is highly insecure and must NOT be
 * used for any purpose except testing
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>

#define OSSLTEST_LIB_NAME "OSSLTEST"
#include "e_ossltest_err.c"

/* Engine Id and Name */
static const char *engine_ossltest_id = "ossltest";
static const char *engine_ossltest_name = "OpenSSL Test engine support";


/* Engine Lifetime functions */
static int ossltest_destroy(ENGINE *e);
static int ossltest_init(ENGINE *e);
static int ossltest_finish(ENGINE *e);
void ENGINE_load_ossltest(void);


/* Set up digests */
static int ossltest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

static int ossltest_digest_nids[] = {
    NID_md5, NID_sha1, NID_sha256, NID_sha384, NID_sha512, 0
};

/* MD5 */
static int digest_md5_init(EVP_MD_CTX *ctx);
static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md);

static const EVP_MD digest_md5 = {
    NID_md5,
    NID_md5WithRSAEncryption,
    MD5_DIGEST_LENGTH,
    0,
    digest_md5_init,
    digest_md5_update,
    digest_md5_final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    MD5_CBLOCK,
    sizeof(EVP_MD *) + sizeof(MD5_CTX),
};

/* SHA1 */
static int digest_sha1_init(EVP_MD_CTX *ctx);
static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static const EVP_MD digest_sha1 = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    digest_sha1_init,
    digest_sha1_update,
    digest_sha1_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

/* SHA256 */
static int digest_sha256_init(EVP_MD_CTX *ctx);
static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

static const EVP_MD digest_sha256 = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    digest_sha256_init,
    digest_sha256_update,
    digest_sha256_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA256_CTX),
};

/* SHA384/SHA512 */
static int digest_sha384_init(EVP_MD_CTX *ctx);
static int digest_sha512_init(EVP_MD_CTX *ctx);
static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md);

static const EVP_MD digest_sha384 = {
    NID_sha384,
    NID_sha384WithRSAEncryption,
    SHA384_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    digest_sha384_init,
    digest_sha512_update,
    digest_sha384_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

static const EVP_MD digest_sha512 = {
    NID_sha512,
    NID_sha512WithRSAEncryption,
    SHA512_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    digest_sha512_init,
    digest_sha512_update,
    digest_sha512_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

/* Setup ciphers */
static int ossltest_ciphers(ENGINE *, const EVP_CIPHER **,
                            const int **, int);

static int ossltest_cipher_nids[] = {
    NID_aes_128_cbc, 0
};

/* AES128 */

int ossltest_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int ossltest_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);

static const EVP_CIPHER ossltest_aes_128_cbc = { \
    NID_aes_128_cbc,
    16, /* block size */
    16, /* key len */
    16, /* iv len */
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE,
    ossltest_aes128_init_key,
    ossltest_aes128_cbc_cipher,
    NULL,
    0, /* We don't know the size of cipher_data at compile time */
    NULL,NULL,NULL,NULL
};


static int bind_ossltest(ENGINE *e)
{
    /* Ensure the ossltest error handling is set up */
    ERR_load_OSSLTEST_strings();

    if (!ENGINE_set_id(e, engine_ossltest_id)
        || !ENGINE_set_name(e, engine_ossltest_name)
        || !ENGINE_set_digests(e, ossltest_digests)
        || !ENGINE_set_ciphers(e, ossltest_ciphers)
        || !ENGINE_set_destroy_function(e, ossltest_destroy)
        || !ENGINE_set_init_function(e, ossltest_init)
        || !ENGINE_set_finish_function(e, ossltest_finish)) {
        OSSLTESTerr(OSSLTEST_F_BIND_OSSLTEST, OSSLTEST_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_ossltest_id) != 0))
        return 0;
    if (!bind_ossltest(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static ENGINE *engine_ossltest(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_ossltest(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_ossltest(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_ossltest();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


static int ossltest_init(ENGINE *e)
{
    return 1;
}


static int ossltest_finish(ENGINE *e)
{
    return 1;
}


static int ossltest_destroy(ENGINE *e)
{
    ERR_unload_OSSLTEST_strings();
    return 1;
}

static int ossltest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = ossltest_digest_nids;
        return (sizeof(ossltest_digest_nids) -
                1) / sizeof(ossltest_digest_nids[0]);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_md5:
        *digest = &digest_md5;
        break;
    case NID_sha1:
        *digest = &digest_sha1;
        break;
    case NID_sha256:
        *digest = &digest_sha256;
        break;
    case NID_sha384:
        *digest = &digest_sha384;
        break;
    case NID_sha512:
        *digest = &digest_sha512;
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static int ossltest_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = ossltest_cipher_nids;
        return (sizeof(ossltest_cipher_nids) - 1)
               / sizeof(ossltest_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = &ossltest_aes_128_cbc;
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
#define data(ctx) ((MD5_CTX *)(ctx)->md_data)
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
#define data(ctx) ((SHA_CTX *)(ctx)->md_data)
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
#define data(ctx) ((SHA256_CTX *)(ctx)->md_data)
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
#define data(ctx) ((SHA512_CTX *)(ctx)->md_data)
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

int ossltest_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    if (ctx->cipher_data == NULL) {
        /*
         * Normally cipher_data is allocated automatically for an engine but
         * we don't know the ctx_size as compile time so we have to do it at
         * run time
         */
        ctx->cipher_data = OPENSSL_zalloc(EVP_aes_128_cbc()->ctx_size);
        if (ctx->cipher_data == NULL) {
            OSSLTESTerr(OSSLTEST_F_OSSLTEST_AES128_INIT_KEY,
                        ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return EVP_aes_128_cbc()->init(ctx, key, iv, enc);
}

int ossltest_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf;
    int ret;

    tmpbuf = OPENSSL_malloc(inl);
    if (tmpbuf == NULL)
        return -1;

    /* Remember what we were asked to encrypt */
    memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    ret = EVP_aes_128_cbc()->do_cipher(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    memcpy(out, tmpbuf, inl);
    OPENSSL_free(tmpbuf);

    return ret;
}
