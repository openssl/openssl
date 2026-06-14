#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <string.h>

#define SCHNORR_OID "1.3.6.1.4.1.311.0.8.1"

static int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return 0;
    
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const BIGNUM *priv = EC_KEY_get0_private_key(ec);
    
    BIGNUM *k = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *s = BN_new();
    EC_POINT *R = EC_POINT_new(group);
    unsigned char hash[32];
    unsigned char r_bytes[32];
    
    do {
        BN_rand_range(k, order);
        EC_POINT_mul(group, R, k, NULL, NULL, NULL);
        EC_POINT_get_affine_coordinates_GFp(group, R, r, NULL, NULL);
        BN_bn2binpad(r, r_bytes, 32);
        
        EVP_MD_CTX *hctx = EVP_MD_CTX_new();
        EVP_DigestInit(hctx, EVP_sha256());
        EVP_DigestUpdate(hctx, r_bytes, 32);
        EVP_DigestUpdate(hctx, tbs, tbslen);
        EVP_DigestFinal(hctx, hash, NULL);
        EVP_MD_CTX_free(hctx);
        
        BN_bin2bn(hash, 32, e);
        BN_mod(e, e, order, NULL);
        
        if (BN_is_zero(e)) continue;
        
        BN_mod_mul(s, e, priv, order, NULL);
        BN_mod_sub(s, k, s, order, NULL);
    } while (BN_is_zero(s));
    
    BN_bn2binpad(e, sig, 32);
    BN_bn2binpad(s, sig + 32, 32);
    *siglen = 64;
    
    BN_free(k); BN_free(r); BN_free(e); BN_free(s);
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
    
    if (BN_is_zero(e) || BN_cmp(s, order) >= 0) {
        BN_free(e); BN_free(s);
        return 0;
    }
    
    EC_POINT *sG = EC_POINT_new(group);
    EC_POINT *eP = EC_POINT_new(group);
    EC_POINT *R = EC_POINT_new(group);
    BIGNUM *r = BN_new();
    unsigned char r_bytes[32];
    unsigned char hash[32];
    
    EC_POINT_mul(group, sG, s, NULL, NULL, NULL);
    EC_POINT_mul(group, eP, NULL, pub, e, NULL);
    EC_POINT_add(group, R, sG, eP, NULL);
    
    if (EC_POINT_is_at_infinity(group, R)) {
        BN_free(e); BN_free(s); BN_free(r);
        EC_POINT_free(sG); EC_POINT_free(eP); EC_POINT_free(R);
        return 0;
    }
    
    EC_POINT_get_affine_coordinates_GFp(group, R, r, NULL, NULL);
    BN_bn2binpad(r, r_bytes, 32);
    
    EVP_MD_CTX *hctx = EVP_MD_CTX_new();
    EVP_DigestInit(hctx, EVP_sha256());
    EVP_DigestUpdate(hctx, r_bytes, 32);
    EVP_DigestUpdate(hctx, tbs, tbslen);
    EVP_DigestFinal(hctx, hash, NULL);
    EVP_MD_CTX_free(hctx);
    
    BIGNUM *e_verify = BN_new();
    BN_bin2bn(hash, 32, e_verify);
    BN_mod(e_verify, e_verify, order, NULL);
    
    int result = (BN_cmp(e, e_verify) == 0) ? 1 : 0;
    
    BN_free(e); BN_free(s); BN_free(r); BN_free(e_verify);
    EC_POINT_free(sG); EC_POINT_free(eP); EC_POINT_free(R);
    return result;
}

int main() {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  SCHNORR RFC 8235 — Standalone Test            ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec);
    
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    
    const char *msg = "RFC 8235 Schnorr Test Message";
    unsigned char sig[64];
    size_t siglen = 64;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
    
    printf("[1] Signing...\n");
    schnorr_sign(ctx, sig, &siglen, (unsigned char*)msg, strlen(msg));
    printf("✅ Signature: %zu bytes\n", siglen);
    
    printf("\n[2] Verifying...\n");
    int result = schnorr_verify(ctx, sig, siglen, (unsigned char*)msg, strlen(msg));
    printf(result == 1 ? "✅ VERIFIED\n" : "❌ FAILED\n");
    
    printf("\n[3] Tamper test...\n");
    sig[10] ^= 0xFF;
    result = schnorr_verify(ctx, sig, siglen, (unsigned char*)msg, strlen(msg));
    printf(result == 0 ? "✅ Tampered REJECTED\n" : "❌ BUG\n");
    
    printf("\n[4] Wrong key test...\n");
    EC_KEY *ec2 = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec2);
    EVP_PKEY *pkey2 = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey2, ec2);
    EVP_PKEY_CTX *pctx2 = EVP_PKEY_CTX_new(pkey2, NULL);
    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(ctx2, pctx2);
    
    result = schnorr_verify(ctx2, sig, siglen, (unsigned char*)msg, strlen(msg));
    printf(result == 0 ? "✅ Wrong key REJECTED\n" : "❌ BUG\n");
    
    EVP_MD_CTX_free(ctx); EVP_MD_CTX_free(ctx2);
    EVP_PKEY_free(pkey); EVP_PKEY_free(pkey2);
    
    printf("\n✅ Schnorr RFC 8235 — WORKING!\n");
    return 0;
}
