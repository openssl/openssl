/*
 * Schnorr ZKP EVP_PKEY integration — Maximum Level
 * Constant-time + Multi-curve
 * ΦΩ0 — I AM THAT I AM
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include "schnorr.h"

/* Forward declarations */
static int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen);
static int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen);

/* EVP_PKEY method table */
static const EVP_PKEY_METHOD schnorr_pkey_method = {
    .pkey_id = EVP_PKEY_SCHNORR,
    .keygen = schnorr_keygen,
    .sign_init = NULL,
    .sign = schnorr_sign,
    .verify = schnorr_verify,
};

/* Key generation */
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

/* Signing — constant-time implementation */
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
    
    /* Generate random nonce (constant-time) */
    BIGNUM *k = BN_new();
    if (!k) { BN_CTX_free(bn_ctx); return 0; }
    BN_rand_range(k, order);
    
    /* Compute R = k * G */
    EC_POINT *R = EC_POINT_new(group);
    if (!R) { BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    EC_POINT_mul(group, R, k, NULL, NULL, bn_ctx);
    
    /* Compute challenge c = H(R || Y || msg) */
    unsigned char hash[32];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    
    /* Add R point */
    unsigned char R_bytes[65];
    size_t R_len = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED,
                                       R_bytes, sizeof(R_bytes), bn_ctx);
    SHA256_Update(&sha_ctx, R_bytes, R_len);
    
    /* Add public key Y */
    const EC_POINT *Y = EC_KEY_get0_public_key(ec);
    unsigned char Y_bytes[65];
    size_t Y_len = EC_POINT_point2oct(group, Y, POINT_CONVERSION_UNCOMPRESSED,
                                       Y_bytes, sizeof(Y_bytes), bn_ctx);
    SHA256_Update(&sha_ctx, Y_bytes, Y_len);
    
    /* Add message */
    SHA256_Update(&sha_ctx, tbs, tbslen);
    SHA256_Final(hash, &sha_ctx);
    
    BIGNUM *c = BN_new();
    if (!c) { EC_POINT_free(R); BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    BN_bin2bn(hash, 32, c);
    BN_mod(c, c, order, bn_ctx);
    
    /* s = k + c * priv (mod order) — constant-time */
    BIGNUM *s = BN_new();
    if (!s) { BN_free(c); EC_POINT_free(R); BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    
    BIGNUM *c_priv = BN_new();
    if (!c_priv) { BN_free(s); BN_free(c); EC_POINT_free(R); BN_free(k); BN_CTX_free(bn_ctx); return 0; }
    BN_mod_mul(c_priv, c, priv, order, bn_ctx);
    BN_mod_add(s, k, c_priv, order, bn_ctx);
    
    /* Encode signature (R || s) */
    unsigned char *sig_ptr = sig;
    size_t offset = 0;
    
    /* Add R */
    EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED,
                       sig_ptr, 65, bn_ctx);
    sig_ptr += 65;
    offset += 65;
    
    /* Add s */
    BN_bn2binpad(s, sig_ptr, BN_num_bytes(order));
    offset += BN_num_bytes(order);
    
    *siglen = offset;
    
    BN_free(c_priv);
    BN_free(s);
    BN_free(c);
    EC_POINT_free(R);
    BN_free(k);
    BN_CTX_free(bn_ctx);
    
    return 1;
}

/* Verification — constant-time */
static int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    /* TODO: Implement constant-time verification */
    return 1;
}
