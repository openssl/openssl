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
    return BLAKE2s_Init(EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return BLAKE2s_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return BLAKE2s_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD blake2s_md = {
    NID_blake2s,
    0,
    BLAKE2S_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    0,
    sizeof(EVP_MD *) + sizeof(BLAKE2S_CTX),
};

const EVP_MD *EVP_blake2s(void)
{
    return (&blake2s_md);
}
#endif
