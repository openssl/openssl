#ifdef HAVE_LIBOQS
/* Schnorr + Falcon-1024 Hybrid Signature
 * 
 * Classical: Schnorr Σ-Protocol (RFC 8235, secp256k1) — 128-bit
 * Post-Quantum: Falcon-1024 (NIST Level 5) — 230-bit PQ
 * 
 * Composite signature: schnorr_sig || falcon1024_sig
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <oqs/oqs.h>
#include "schnorr_local.h"

#define HYBRID_OID "1.3.9999.5.10241024"

/* Forward declarations */
int schnorr_sign_raw(const unsigned char *msg, size_t msg_len,
                      const unsigned char *priv_key, size_t priv_key_len,
                      unsigned char *sig, size_t *sig_len);

int schnorr_verify_raw(const unsigned char *msg, size_t msg_len,
                        const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *sig, size_t sig_len);

typedef struct {
    uint8_t *falcon_pubkey;
    uint8_t *falcon_privkey;
    EC_KEY *schnorr_key;  /* secp256k1 keypair */
    size_t falcon_pubkey_len;
    size_t falcon_privkey_len;
} HYBRID_KEY;

static int hybrid_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    HYBRID_KEY *key = OPENSSL_zalloc(sizeof(HYBRID_KEY));
    if (!key) return 0;
    
    /* Falcon-1024 keypair */
    key->falcon_pubkey = OPENSSL_malloc(OQS_SIG_falcon_1024_length_public_key);
    key->falcon_privkey = OPENSSL_malloc(OQS_SIG_falcon_1024_length_secret_key);
    key->falcon_pubkey_len = OQS_SIG_falcon_1024_length_public_key;
    key->falcon_privkey_len = OQS_SIG_falcon_1024_length_secret_key;
    
    if (!key->falcon_pubkey || !key->falcon_privkey) goto err;
    if (OQS_SIG_falcon_1024_keypair(key->falcon_pubkey, key->falcon_privkey) != OQS_SUCCESS) goto err;
    
    /* Schnorr secp256k1 keypair */
    key->schnorr_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key->schnorr_key) goto err;
    if (!EC_KEY_generate_key(key->schnorr_key)) goto err;
    
    EVP_PKEY_assign(pkey, OBJ_txt2nid(HYBRID_OID), key);
    return 1;
    
err:
    OPENSSL_free(key->falcon_pubkey);
    OPENSSL_free(key->falcon_privkey);
    EC_KEY_free(key->schnorr_key);
    OPENSSL_free(key);
    return 0;
}

static int hybrid_sign(EVP_MD_CTX *ctx, unsigned char *sig_out, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    HYBRID_KEY *key = EVP_PKEY_get0(pkey);
    
    /* Schnorr sign */
    unsigned char schnorr_sig[128];
    size_t schnorr_len = sizeof(schnorr_sig);
    
    if (!schnorr_sign_raw(tbs, tbslen, 
                          (const unsigned char *)EC_KEY_get0_private_key(key->schnorr_key),
                          BN_num_bytes(EC_KEY_get0_private_key(key->schnorr_key)),
                          schnorr_sig, &schnorr_len))
        return 0;
    
    /* Falcon-1024 sign */
    unsigned char *falcon_sig = OPENSSL_malloc(OQS_SIG_falcon_1024_length_signature);
    size_t falcon_len = OQS_SIG_falcon_1024_length_signature;
    
    if (OQS_SIG_falcon_1024_sign(falcon_sig, &falcon_len, tbs, tbslen, 
                                   key->falcon_privkey) != OQS_SUCCESS) {
        OPENSSL_free(falcon_sig);
        return 0;
    }
    
    /* Composite: schnorr_sig || falcon_sig */
    memcpy(sig_out, schnorr_sig, schnorr_len);
    memcpy(sig_out + schnorr_len, falcon_sig, falcon_len);
    *siglen = schnorr_len + falcon_len;
    
    OPENSSL_free(falcon_sig);
    return 1;
}

static int hybrid_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    HYBRID_KEY *key = EVP_PKEY_get0(pkey);
    
    /* Split composite signature */
    size_t schnorr_len = 64;  /* Schnorr sig size for secp256k1 */
    size_t falcon_len = siglen - schnorr_len;
    
    if (siglen < schnorr_len + 1) return 0;
    
    /* Schnorr verify */
    if (!schnorr_verify_raw(tbs, tbslen,
                             (const unsigned char *)EC_KEY_get0_public_key(key->schnorr_key),
                             0, /* simplified */
                             sig, schnorr_len))
        return 0;
    
    /* Falcon-1024 verify */
    if (OQS_SIG_falcon_1024_verify(tbs, tbslen, sig + schnorr_len, 
                                     falcon_len, key->falcon_pubkey) != OQS_SUCCESS)
        return 0;
    
    return 1;
}

static EVP_PKEY_METHOD *hybrid_pkey_meth = NULL;

int OPENSSL_schnorr_falcon1024_init(void)
{
    int nid = OBJ_create(HYBRID_OID, "SchnorrFalcon1024",
                         "Hybrid Schnorr+Falcon-1024 Signature");
    if (nid == NID_undef) return 0;
    
    hybrid_pkey_meth = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (!hybrid_pkey_meth) return 0;
    
    EVP_PKEY_meth_set_keygen(hybrid_pkey_meth, NULL, hybrid_keygen);
    EVP_PKEY_meth_set_sign(hybrid_pkey_meth, NULL, hybrid_sign);
    EVP_PKEY_meth_set_verify(hybrid_pkey_meth, NULL, hybrid_verify);
    
    EVP_PKEY_meth_add0(hybrid_pkey_meth);
    return 1;
}

void OPENSSL_schnorr_falcon1024_cleanup(void)
{
    EVP_PKEY_meth_free(hybrid_pkey_meth);
}
#endif /* HAVE_LIBOQS */
