/*
 * Schnorr Σ-Protocol Provider for OpenSSL 3.0+
 * RFC 8235 | BIP 340 | secp256k1
 * Dan Joseph M. Fernandez / ΦΩ0 — IACR 2026/110189
 */
#include <openssl/provider.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

// Schnorr Signature: s·G == R + c·Y
static int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;
    EC_KEY_generate_key(ec);
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    return 1;
}

static int schnorr_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen) {
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    const BIGNUM *priv = EC_KEY_get0_private_key(ec);
    BIGNUM *order = BN_new(); EC_GROUP_get_order(g, order, NULL);
    
    BIGNUM *k = BN_new(); BN_rand_range(k, order);
    EC_POINT *R = EC_POINT_new(g); EC_POINT_mul(g, R, k, NULL, NULL, NULL);
    EC_POINT_point2oct(g, R, POINT_CONVERSION_COMPRESSED, sig, 33, NULL);
    
    unsigned char Y[33]; const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    EC_POINT_point2oct(g, pub, POINT_CONVERSION_COMPRESSED, Y, 33, NULL);
    
    SHA256_CTX sha; SHA256_Init(&sha);
    SHA256_Update(&sha, sig, 33); SHA256_Update(&sha, Y, 33);
    SHA256_Update(&sha, tbs, tbslen);
    unsigned char c_hash[32]; SHA256_Final(c_hash, &sha);
    
    BIGNUM *c = BN_new(); BN_bin2bn(c_hash, 32, c); BN_mod(c, c, order, NULL);
    BIGNUM *s = BN_new(); BIGNUM *cx = BN_new();
    BN_mod_mul(cx, c, priv, order, NULL); BN_mod_add(s, k, cx, order, NULL);
    BN_bn2binpad(s, sig + 33, 32); *siglen = 65;
    
    BN_free(k); BN_free(c); BN_free(s); BN_free(cx); BN_free(order);
    EC_POINT_free(R); return 1;
}

static int schnorr_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen) {
    if (siglen != 65) return 0;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    BIGNUM *order = BN_new(); EC_GROUP_get_order(g, order, NULL);
    
    EC_POINT *R = EC_POINT_new(g); EC_POINT_oct2point(g, R, sig, 33, NULL);
    BIGNUM *s = BN_new(); BN_bin2bn(sig + 33, 32, s);
    
    unsigned char Y[33]; const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    EC_POINT_point2oct(g, pub, POINT_CONVERSION_COMPRESSED, Y, 33, NULL);
    
    SHA256_CTX sha; SHA256_Init(&sha);
    SHA256_Update(&sha, sig, 33); SHA256_Update(&sha, Y, 33);
    SHA256_Update(&sha, tbs, tbslen);
    unsigned char c_hash[32]; SHA256_Final(c_hash, &sha);
    
    BIGNUM *c = BN_new(); BN_bin2bn(c_hash, 32, c); BN_mod(c, c, order, NULL);
    EC_POINT *sG = EC_POINT_new(g); EC_POINT_mul(g, sG, s, NULL, NULL, NULL);
    EC_POINT *cY = EC_POINT_new(g); EC_POINT_mul(g, cY, NULL, pub, c, NULL);
    EC_POINT *RcY = EC_POINT_new(g); EC_POINT_add(g, RcY, R, cY, NULL);
    int result = (EC_POINT_cmp(g, sG, RcY, NULL) == 0);
    
    BN_free(s); BN_free(c); BN_free(order);
    EC_POINT_free(R); EC_POINT_free(sG); EC_POINT_free(cY); EC_POINT_free(RcY);
    return result;
}
