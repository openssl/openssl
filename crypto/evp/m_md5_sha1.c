/* crypto/evp/m_md5_sha1.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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

#if !defined(OPENSSL_NO_MD5) && !defined(OPENSSL_NO_SHA1)

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/x509.h>
# include <openssl/md5.h>
# include <openssl/sha.h>
# include "internal/cryptlib.h"
# ifndef OPENSSL_NO_RSA
#  include <openssl/rsa.h>
# endif

struct md5_sha1_ctx {
    MD5_CTX md5;
    SHA_CTX sha1;
};

static int init(EVP_MD_CTX *ctx)
{
    struct md5_sha1_ctx *mctx = ctx->md_data;
    if (!MD5_Init(&mctx->md5))
        return 0;
    return SHA1_Init(&mctx->sha1);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct md5_sha1_ctx *mctx = ctx->md_data;
    if (!MD5_Update(&mctx->md5, data, count))
        return 0;
    return SHA1_Update(&mctx->sha1, data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct md5_sha1_ctx *mctx = ctx->md_data;
    if (!MD5_Final(md, &mctx->md5))
        return 0;
    return SHA1_Final(md + MD5_DIGEST_LENGTH, &mctx->sha1);
}

static int ctrl(EVP_MD_CTX *ctx, int cmd, int mslen, void *ms)
{
    unsigned char padtmp[48];
    unsigned char md5tmp[MD5_DIGEST_LENGTH];
    unsigned char sha1tmp[SHA_DIGEST_LENGTH];
    struct md5_sha1_ctx *mctx = ctx->md_data;

    if (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        return 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    if (mslen != 48)
        return 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    if (update(ctx, ms, mslen) <= 0)
        return 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, sizeof(padtmp));

    if (!MD5_Update(&mctx->md5, padtmp, sizeof(padtmp)))
        return 0;

    if (!MD5_Final(md5tmp, &mctx->md5))
        return 0;

    if (!SHA1_Update(&mctx->sha1, padtmp, 40))
        return 0;

    if (!SHA1_Final(sha1tmp, &mctx->sha1))
        return 0;

    /* Reinitialise context */

    if (!init(ctx))
        return 0;

    if (update(ctx, ms, mslen) <= 0)
        return 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, sizeof(padtmp));

    if (!MD5_Update(&mctx->md5, padtmp, sizeof(padtmp)))
        return 0;

    if (!MD5_Update(&mctx->md5, md5tmp, sizeof(md5tmp)))
        return 0;

    if (!SHA1_Update(&mctx->sha1, padtmp, 40))
        return 0;

    if (!SHA1_Update(&mctx->sha1, sha1tmp, sizeof(sha1tmp)))
        return 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */

    OPENSSL_cleanse(md5tmp, sizeof(md5tmp));
    OPENSSL_cleanse(sha1tmp, sizeof(sha1tmp));

    return 1;

}

static const EVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    MD5_CBLOCK,
    sizeof(EVP_MD *) + sizeof(struct md5_sha1_ctx),
    ctrl
};

const EVP_MD *EVP_md5_sha1(void)
{
    return &md5_sha1_md;
}
#endif
