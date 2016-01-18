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
