#include <openssl/evp.h>
#include <openssl/core.h>
#include "evp_ml-dsa.h"
#include "api.h"
#include "params.h"

static int ml_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    unsigned char *pk = OPENSSL_malloc(ML_DSA_PUBLIC_KEY_BYTES);
    unsigned char *sk = OPENSSL_malloc(ML_DSA_PRIVATE_KEY_BYTES);
    
    if (!pk || !sk) {
        OPENSSL_free(pk);
        OPENSSL_free(sk);
        return 0;
    }
    
    int ret = crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        OPENSSL_free(pk);
        OPENSSL_free(sk);
        return 0;
    }
    
    /* I-assign ang public key sa EVP_PKEY */
    EVP_PKEY_assign(pkey, EVP_PKEY_ML_DSA, pk);
    
    /* I-store ang private key sa isang separate na structure */
    OPENSSL_free(sk);  /* TODO: I-store properly */
    
    return 1;
}

static int ml_dsa_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_MD_CTX_get0_pkey(ctx);
    unsigned char *sk = EVP_PKEY_get0(pkey);  /* TODO: Kunin ang tamang private key */
    unsigned long long smlen;
    
    int ret = crypto_sign(sig, &smlen, tbs, tbslen, sk);
    *siglen = smlen;
    
    return (ret == 0) ? 1 : 0;
}

static int ml_dsa_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_MD_CTX_get0_pkey(ctx);
    unsigned char *pk = EVP_PKEY_get0(pkey);
    unsigned char *m = OPENSSL_malloc(tbslen + siglen);
    unsigned long long mlen;
    
    if (!m) return 0;
    
    int ret = crypto_sign_open(m, &mlen, sig, siglen, pk);
    OPENSSL_free(m);
    
    if (ret == 0 && mlen == tbslen && memcmp(m, tbs, tbslen) == 0) {
        return 1;
    }
    return 0;
}
