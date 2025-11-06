#ifndef OSSL_CRYPTO_EVP_B64_AVX2_H
# define OSSL_CRYPTO_EVP_B64_AVX2_H

# include <openssl/evp.h>

int encode_base64_avx2(EVP_ENCODE_CTX *ctx,
                       unsigned char *out, const unsigned char *src, int srclen,
                       int newlines, int *wrap_cnt);

#endif
