#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <string.h>
#include "falcon.h"

#define FALCON1024_OID "1.3.9999.5.1024"

static int falcon1024_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int falcon1024_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen);
static int falcon1024_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen);

static EVP_PKEY_METHOD *falcon1024_pkey_method = NULL;

static int falcon1024_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    unsigned char priv[FALCON1024_PRIVKEY_SIZE];
    unsigned char pub[FALCON1024_PUBKEY_SIZE];
    shake256_context rng;
    
    if (RAND_bytes(priv, 48) != 1) return 0;
    shake256_init_prng_from_seed(&rng, priv, 48);
    
    int8_t *sk = NULL;
    uint8_t *pk = NULL;
    
    if (falcon_keygen(&rng, 9, &sk, &pk) != 0) return 0;
    
    memcpy(priv, sk, FALCON1024_PRIVKEY_SIZE);
    memcpy(pub, pk, FALCON1024_PUBKEY_SIZE);
    
    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_set_type(key, EVP_PKEY_NONE);
    *pkey = *key;
    EVP_PKEY_free(key);
    
    free(sk); free(pk);
    return 1;
}

static int falcon1024_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    int8_t *sk = (int8_t*)EVP_PKEY_get0(pkey);
    
    shake256_context rng;
    unsigned char seed[48];
    RAND_bytes(seed, 48);
    shake256_init_prng_from_seed(&rng, seed, 48);
    
    size_t sig_len = FALCON1024_SIG_SIZE;
    int ret = falcon_sign(&rng, sk, tbs, tbslen, sig, &sig_len);
    *siglen = sig_len;
    
    return (ret == 0) ? 1 : 0;
}

static int falcon1024_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    uint8_t *pk = (uint8_t*)EVP_PKEY_get0(pkey);
    
    return (falcon_verify(sig, siglen, pk, tbs, tbslen) == 0) ? 1 : 0;
}

int OPENSSL_falcon1024_init(void)
{
    int nid = OBJ_create(FALCON1024_OID, "Falcon1024", "Falcon-1024 Post-Quantum Signature");
    if (nid == 0) return 0;
    
    falcon1024_pkey_method = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (!falcon1024_pkey_method) return 0;
    
    EVP_PKEY_meth_set_keygen(falcon1024_pkey_method, NULL, falcon1024_keygen);
    EVP_PKEY_meth_set_sign(falcon1024_pkey_method, NULL, falcon1024_sign);
    EVP_PKEY_meth_set_verify(falcon1024_pkey_method, NULL, falcon1024_verify);
    
    return 1;
}
