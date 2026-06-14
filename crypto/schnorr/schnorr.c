#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define SCHNORR_RFC8235_OID "1.3.6.1.4.1.311.0.8.1"

static int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen);
static int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen);

static EVP_PKEY_METHOD *schnorr_pkey_method = NULL;

static int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;
    if (!EC_KEY_generate_key(ec)) { EC_KEY_free(ec); return 0; }
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    return 1;
}

static int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return 0;
    
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    
    BIGNUM *k = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = (BIGNUM *)EC_KEY_get0_private_key(ec);
    EC_POINT *R = EC_POINT_new(group);
    unsigned char hash[32];
    
    BN_rand_range(k, order);
    EC_POINT_mul(group, R, k, NULL, NULL, NULL);
    EC_POINT_get_affine_coordinates_GFp(group, R, x, NULL, NULL);
    
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(hash_ctx, tbs, tbslen);
    unsigned char x_bytes[32];
    BN_bn2bin(x, x_bytes);
    EVP_DigestUpdate(hash_ctx, x_bytes, 32);
    EVP_DigestFinal_ex(hash_ctx, hash, NULL);
    EVP_MD_CTX_free(hash_ctx);
    
    BN_bin2bn(hash, 32, e);
    BN_mod(e, e, order, NULL);
    
    BIGNUM *s = BN_new();
    BN_mod_mul(s, e, d, order, NULL);
    BN_mod_sub(s, k, s, order, NULL);
    
    BN_bn2bin(e, sig);
    BN_bn2bin(s, sig + 32);
    *siglen = 64;
    
    BN_free(k); BN_free(x); BN_free(e); BN_free(s);
    EC_POINT_free(R);
    return 1;
}

static int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    if (siglen != 64) return 0;
    
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return 0;
    
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    
    BIGNUM *e = BN_new();
    BIGNUM *s = BN_new();
    BN_bin2bn(sig, 32, e);
    BN_bin2bn(sig + 32, 32, s);
    
    EC_POINT *sG = EC_POINT_new(group);
    EC_POINT *eP = EC_POINT_new(group);
    EC_POINT *R = EC_POINT_new(group);
    BIGNUM *x = BN_new();
    
    EC_POINT_mul(group, sG, s, NULL, NULL, NULL);
    EC_POINT_mul(group, eP, NULL, pub, e, NULL);
    EC_POINT_add(group, R, sG, eP, NULL);
    EC_POINT_get_affine_coordinates_GFp(group, R, x, NULL, NULL);
    
    unsigned char hash[32];
    unsigned char x_bytes[32];
    BN_bn2bin(x, x_bytes);
    
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(hash_ctx, tbs, tbslen);
    EVP_DigestUpdate(hash_ctx, x_bytes, 32);
    EVP_DigestFinal_ex(hash_ctx, hash, NULL);
    EVP_MD_CTX_free(hash_ctx);
    
    BIGNUM *e_verify = BN_new();
    BN_bin2bn(hash, 32, e_verify);
    BN_mod(e_verify, e_verify, order, NULL);
    
    int result = (BN_cmp(e, e_verify) == 0) ? 1 : 0;
    
    BN_free(e); BN_free(s); BN_free(x); BN_free(e_verify);
    EC_POINT_free(sG); EC_POINT_free(eP); EC_POINT_free(R);
    return result;
}

int OPENSSL_schnorr_init(void)
{
    int nid = OBJ_create(SCHNORR_RFC8235_OID, "Schnorr", "Schnorr Signature (RFC 8235)");
    if (nid == 0) return 0;
    
    schnorr_pkey_method = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (!schnorr_pkey_method) return 0;
    
    EVP_PKEY_meth_set_keygen(schnorr_pkey_method, NULL, schnorr_keygen);
    EVP_PKEY_meth_set_sign(schnorr_pkey_method, NULL, schnorr_sign);
    EVP_PKEY_meth_set_verify(schnorr_pkey_method, NULL, schnorr_verify);
    
    return 1;
}

void OPENSSL_schnorr_cleanup(void)
{
    EVP_PKEY_meth_free(schnorr_pkey_method);
}
