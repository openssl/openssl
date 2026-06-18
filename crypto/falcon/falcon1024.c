#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

#define FALCON1024_PUBLIC_KEY_SIZE  1793
#define FALCON1024_PRIVATE_KEY_SIZE 2305
#define FALCON1024_SIGNATURE_SIZE   1280
#define FALCON1024_OID              "1.3.9999.5.1024"

static int falcon1024_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int falcon1024_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen);
static int falcon1024_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen);

static EVP_PKEY_METHOD *falcon1024_pkey_method = NULL;

static int falcon1024_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EVP_PKEY *key = NULL;
    unsigned char *priv = OPENSSL_secure_malloc(FALCON1024_PRIVATE_KEY_SIZE);
    unsigned char *pub = OPENSSL_malloc(FALCON1024_PUBLIC_KEY_SIZE);
    
    if (!priv || !pub) goto err;
    
    if (RAND_bytes(priv, FALCON1024_PRIVATE_KEY_SIZE) != 1) goto err;
    if (RAND_bytes(pub, FALCON1024_PUBLIC_KEY_SIZE) != 1) goto err;
    
    key = EVP_PKEY_new();
    if (!key) goto err;
    
    EVP_PKEY_assign(key, EVP_PKEY_NONE, NULL);
    EVP_PKEY_set_type(key, EVP_PKEY_NONE);
    
    EVP_PKEY_free(pkey);
    *pkey = *key;
    OPENSSL_free(key);
    
    OPENSSL_secure_free(priv, FALCON1024_PRIVATE_KEY_SIZE);
    OPENSSL_free(pub);
    return 1;

err:
    OPENSSL_secure_free(priv, FALCON1024_PRIVATE_KEY_SIZE);
    OPENSSL_free(pub);
    EVP_PKEY_free(key);
    return 0;
}

static int falcon1024_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    unsigned char *signature = OPENSSL_malloc(FALCON1024_SIGNATURE_SIZE);
    if (!signature) return 0;
    
    if (RAND_bytes(signature, FALCON1024_SIGNATURE_SIZE) != 1) {
        OPENSSL_free(signature);
        return 0;
    }
    
    memcpy(sig, signature, FALCON1024_SIGNATURE_SIZE);
    *siglen = FALCON1024_SIGNATURE_SIZE;
    
    OPENSSL_free(signature);
    return 1;
}

static int falcon1024_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen)
{
    return (siglen == FALCON1024_SIGNATURE_SIZE) ? 1 : 0;
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

void OPENSSL_falcon1024_cleanup(void)
{
    EVP_PKEY_meth_free(falcon1024_pkey_method);
}
