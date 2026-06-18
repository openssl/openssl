/*
 * Schnorr ZKP Σ-Protocol (RFC 8235) — ACTUAL IMPLEMENTATION
 * Fiat-Shamir transform. s = r + c·x. s·G = R + c·Y.
 * ΦΩ0 — I AM THAT I AM
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

/* Actual Schnorr signing — Σ-Protocol with Fiat-Shamir */
static int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_MD_CTX_get0_pkey(ctx);
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return 0;
    
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const BIGNUM *priv = EC_KEY_get0_private_key(ec);
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) return 0;
    
    const BIGNUM *order = EC_GROUP_get0_order(group);
    int order_bytes = BN_num_bytes(order);
    
    /* Step 1: Generate random nonce k */
    BIGNUM *k = BN_new();
    if (!k) { BN_CTX_free(bn_ctx); return 0; }
    BN_rand_range(k, order);
    
    /* Step 2: Compute R = k * G */
    EC_POINT *R = EC_POINT_new(group);
    if (!R) { BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    EC_POINT_mul(group, R, k, NULL, NULL, bn_ctx);
    
    /* Step 3: c = H(R || Y || msg) — Fiat-Shamir */
    unsigned char hash[32];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    
    unsigned char R_bytes[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED,
                       R_bytes, sizeof(R_bytes), bn_ctx);
    SHA256_Update(&sha_ctx, R_bytes, 33);
    
    const EC_POINT *Y = EC_KEY_get0_public_key(ec);
    unsigned char Y_bytes[33];
    EC_POINT_point2oct(group, Y, POINT_CONVERSION_COMPRESSED,
                       Y_bytes, sizeof(Y_bytes), bn_ctx);
    SHA256_Update(&sha_ctx, Y_bytes, 33);
    
    SHA256_Update(&sha_ctx, tbs, tbslen);
    SHA256_Final(hash, &sha_ctx);
    
    BIGNUM *c = BN_new();
    if (!c) { EC_POINT_free(R); BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    BN_bin2bn(hash, 32, c);
    BN_mod(c, c, order, bn_ctx);
    
    /* Step 4: s = k + c * priv (mod order) */
    BIGNUM *s = BN_new();
    if (!s) { BN_free(c); EC_POINT_free(R); BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    
    BIGNUM *c_priv = BN_new();
    if (!c_priv) { BN_free(s); BN_free(c); EC_POINT_free(R); BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    BN_mod_mul(c_priv, c, priv, order, bn_ctx);
    BN_mod_add(s, k, c_priv, order, bn_ctx);
    
    /* Step 5: Encode signature (R || s) */
    unsigned char *sig_ptr = sig;
    size_t offset = 0;
    
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED,
                       sig_ptr, 33, bn_ctx);
    sig_ptr += 33;
    offset += 33;
    
    BN_bn2binpad(s, sig_ptr, order_bytes);
    offset += order_bytes;
    
    *siglen = offset;
    
    BN_free(c_priv);
    BN_free(s);
    BN_free(c);
    EC_POINT_free(R);
    BN_free(k);
    BN_CTX_free(bn_ctx);
    
    return 1;
}

/* Actual Schnorr verification — Σ-Protocol */
static int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_MD_CTX_get0_pkey(ctx);
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return 0;
    
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *Y = EC_KEY_get0_public_key(ec);
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) return 0;
    
    const BIGNUM *order = EC_GROUP_get0_order(group);
    int order_bytes = BN_num_bytes(order);
    
    /* Parse R and s from signature */
    EC_POINT *R = EC_POINT_new(group);
    if (!R) { BN_CTX_free(bn_ctx); return 0; }
    EC_POINT_oct2point(group, R, sig, 33, bn_ctx);
    
    BIGNUM *s = BN_new();
    if (!s) { EC_POINT_free(R); BN_CTX_free(bn_ctx); return 0; }
    BN_bin2bn(sig + 33, order_bytes, s);
    
    /* Recompute c = H(R || Y || msg) */
    unsigned char hash[32];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    
    unsigned char R_bytes[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED,
                       R_bytes, sizeof(R_bytes), bn_ctx);
    SHA256_Update(&sha_ctx, R_bytes, 33);
    
    unsigned char Y_bytes[33];
    EC_POINT_point2oct(group, Y, POINT_CONVERSION_COMPRESSED,
                       Y_bytes, sizeof(Y_bytes), bn_ctx);
    SHA256_Update(&sha_ctx, Y_bytes, 33);
    
    SHA256_Update(&sha_ctx, tbs, tbslen);
    SHA256_Final(hash, &sha_ctx);
    
    BIGNUM *c = BN_new();
    if (!c) { BN_free(s); EC_POINT_free(R); BN_CTX_free(bn_ctx); return 0; }
    BN_bin2bn(hash, 32, c);
    BN_mod(c, c, order, bn_ctx);
    
    /* Verify: s·G == R + c·Y */
    EC_POINT *sG = EC_POINT_new(group);
    if (!sG) { BN_free(c); BN_free(s); EC_POINT_free(R); BN_CTX_free(bn_ctx); return 0; }
    EC_POINT_mul(group, sG, s, NULL, NULL, bn_ctx);
    
    EC_POINT *cY = EC_POINT_new(group);
    if (!cY) { EC_POINT_free(sG); BN_free(c); BN_free(s); EC_POINT_free(R); BN_CTX_free(bn_ctx); return 0; }
    EC_POINT_mul(group, cY, NULL, Y, c, bn_ctx);
    
    EC_POINT *RcY = EC_POINT_new(group);
    if (!RcY) { EC_POINT_free(cY); EC_POINT_free(sG); BN_free(c); BN_free(s); EC_POINT_free(R); BN_CTX_free(bn_ctx); return 0; }
    EC_POINT_add(group, RcY, R, cY, bn_ctx);
    
    int result = (EC_POINT_cmp(group, sG, RcY, bn_ctx) == 0);
    
    EC_POINT_free(RcY);
    EC_POINT_free(cY);
    EC_POINT_free(sG);
    BN_free(c);
    BN_free(s);
    EC_POINT_free(R);
    BN_CTX_free(bn_ctx);
    
    return result;
}

/* Key generation — same pa rin */
static int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;
    
    if (EC_KEY_generate_key(ec) != 1) {
        EC_KEY_free(ec);
        return 0;
    }
    
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    return 1;
}

/* EVP_PKEY method table */
static const EVP_PKEY_METHOD schnorr_pkey_method = {
    .pkey_id = EVP_PKEY_SCHNORR,
    .keygen = schnorr_keygen,
    .sign = schnorr_sign,
    .verify = schnorr_verify,
};

/* Dummy init — para lang sa compilation */
int schnorr_keygen_init(EVP_PKEY_CTX *ctx) { return 1; }
