#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <oqs/oqs.h>
#include <string.h>

#define FALCON1024_OID "1.3.9999.5.1024"

static int falcon1024_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (!sig) return 0;
    
    uint8_t *pk = OPENSSL_malloc(sig->length_public_key);
    uint8_t *sk = OPENSSL_malloc(sig->length_secret_key);
    
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        OPENSSL_free(pk); OPENSSL_free(sk); OQS_SIG_free(sig);
        return 0;
    }
    
    OQS_SIG_free(sig);
    OPENSSL_free(pk); OPENSSL_free(sk);
    return 1;
}

static int falcon1024_sign(EVP_MD_CTX *ctx, unsigned char *sig_out, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (!sig) return 0;
    
    size_t slen = sig->length_signature;
    int ret = OQS_SIG_sign(sig, sig_out, &slen, tbs, tbslen, NULL);
    *siglen = slen;
    OQS_SIG_free(sig);
    
    return (ret == OQS_SUCCESS) ? 1 : 0;
}

static int falcon1024_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen)
{
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (!s) return 0;
    
    int ret = OQS_SIG_verify(s, sig, siglen, tbs, tbslen, NULL);
    OQS_SIG_free(s);
    
    return (ret == OQS_SUCCESS) ? 1 : 0;
}

int OPENSSL_falcon1024_init(void)
{
    int nid = OBJ_create(FALCON1024_OID, "Falcon1024", "Falcon-1024 PQC Signature");
    if (nid == 0) return 0;
    
    EVP_PKEY_METHOD *meth = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (!meth) return 0;
    
    EVP_PKEY_meth_set_keygen(meth, NULL, falcon1024_keygen);
    EVP_PKEY_meth_set_sign(meth, NULL, falcon1024_sign);
    EVP_PKEY_meth_set_verify(meth, NULL, falcon1024_verify);
    
    return 1;
}
