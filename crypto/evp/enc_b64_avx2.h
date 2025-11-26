#ifndef OSSL_CRYPTO_EVP_B64_AVX2_H
# define OSSL_CRYPTO_EVP_B64_AVX2_H

# include <openssl/evp.h>

# if defined(__x86_64) || defined(__x86_64__) || \
    defined(_M_AMD64) || defined(_M_X64)
int encode_base64_avx2(EVP_ENCODE_CTX *ctx,
                       unsigned char *out, const unsigned char *src, int srclen,
                       int newlines, int *wrap_cnt);
# endif

#endif
