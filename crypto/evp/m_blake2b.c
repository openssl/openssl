/*
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.
 * You may use this under the terms of the CC0, the OpenSSL Licence, or the
 * Apache Public License 2.0, at your option.  The terms of these licenses can
 * be found at:
 *
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 * - CC0 1.0 Universal : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 * 
 */

/* crypto/evp/m_blake2b.c */

#include <stdio.h>
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_BLAKE2

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/blake2.h>
# include "internal/blake2_locl.h"
# include "internal/evp_int.h"

static int init(EVP_MD_CTX *ctx)
{
    return BLAKE2b_Init(EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return BLAKE2b_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return BLAKE2b_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD blake2b_md = {
    NID_blake2b,
    0,
    BLAKE2B_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    0,
    sizeof(EVP_MD *) + sizeof(BLAKE2B_CTX),
};

const EVP_MD *EVP_blake2b(void)
{
    return (&blake2b_md);
}
#endif
