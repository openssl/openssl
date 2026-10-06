#ifndef OSSL_CRYPTO_EVP_ENC_B64_AVX2_H
#define OSSL_CRYPTO_EVP_ENC_B64_AVX2_H

#include <openssl/evp.h>
#include <stddef.h>

#include "b64_avx2_common.h"

#ifdef HAVE_AVX2
size_t encode_base64_avx2(EVP_ENCODE_CTX *ctx,
    unsigned char *out, const unsigned char *src, int srclen,
    int newlines, int *wrap_cnt);
#endif

#endif
