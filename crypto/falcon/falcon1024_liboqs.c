#ifdef HAVE_LIBOQS
/* Falcon-1024 Post-Quantum Signature via liboqs
 * NIST FIPS 204 Level 5: 263-bit classical, 230-bit PQ security
 * Public key: 1793 bytes, Signature: ~1271 bytes
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <string.h>

#define FALCON1024_OID "1.3.9999.5.1024"

typedef struct {
    uint8_t *pubkey;
    uint8_t *privkey;
    size_t pubkey_len;
    size_t privkey_len;
} FALCON1024_KEY;

static int falcon1024_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    uint8_t *pk = OPENSSL_malloc(OQS_SIG_falcon_1024_length_public_key);
    uint8_t *sk = OPENSSL_malloc(OQS_SIG_falcon_1024_length_secret_key);
    
    if (!pk || !sk) {
        OPENSSL_free(pk); OPENSSL_free(sk);
        return 0;
    }
    
    if (OQS_SIG_falcon_1024_keypair(pk, sk) != OQS_SUCCESS) {
        OPENSSL_free(pk); OPENSSL_free(sk);
        return 0;
    }
    
    FALCON1024_KEY *key = OPENSSL_malloc(sizeof(FALCON1024_KEY));
    if (!key) { OPENSSL_free(pk); OPENSSL_free(sk); return 0; }
    
    key->pubkey = pk;
    key->privkey = sk;
    key->pubkey_len = OQS_SIG_falcon_1024_length_public_key;
    key->privkey_len = OQS_SIG_falcon_1024_length_secret_key;
    
    EVP_PKEY_assign(pkey, OBJ_txt2nid(FALCON1024_OID), key);
    return 1;
}

static int falcon1024_sign(EVP_MD_CTX *ctx, unsigned char *sig_out, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    FALCON1024_KEY *key = EVP_PKEY_get0(pkey);
    
    size_t slen = OQS_SIG_falcon_1024_length_signature;
    if (OQS_SIG_falcon_1024_sign(sig_out, &slen, tbs, tbslen, key->privkey) != OQS_SUCCESS)
        return 0;
    
    *siglen = slen;
    return 1;
}

static int falcon1024_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    FALCON1024_KEY *key = EVP_PKEY_get0(pkey);
    
    return (OQS_SIG_falcon_1024_verify(tbs, tbslen, sig, siglen, key->pubkey) == OQS_SUCCESS) ? 1 : 0;
}

/* EVP registration */
static EVP_PKEY_METHOD *falcon1024_pkey_meth = NULL;

int OPENSSL_falcon1024_init(void)
{
    int nid = OBJ_create(FALCON1024_OID, "Falcon1024", 
                         "Falcon-1024 Post-Quantum Signature (NIST Level 5)");
    if (nid == NID_undef) return 0;
    
    falcon1024_pkey_meth = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (!falcon1024_pkey_meth) return 0;
    
    EVP_PKEY_meth_set_keygen(falcon1024_pkey_meth, NULL, falcon1024_keygen);
    EVP_PKEY_meth_set_sign(falcon1024_pkey_meth, NULL, falcon1024_sign);
    EVP_PKEY_meth_set_verify(falcon1024_pkey_meth, NULL, falcon1024_verify);
    
    EVP_PKEY_meth_add0(falcon1024_pkey_meth);
    return 1;
}

void OPENSSL_falcon1024_cleanup(void)
{
    EVP_PKEY_meth_free(falcon1024_pkey_meth);
}
#endif /* HAVE_LIBOQS */
