#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

// Direct Schnorr test — no provider, just raw OpenSSL
int main() {
    printf("=== SCHNORR TEST (RAW OPENSSL) ===\n");
    
    // Keygen
    printf("Test 1: Keygen...\n");
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) { printf("❌ FAIL\n"); return 1; }
    EC_KEY_generate_key(ec);
    printf("✅ PASS\n");
    
    // Sign
    printf("Test 2: Sign...\n");
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    const BIGNUM *priv = EC_KEY_get0_private_key(ec);
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(g, order, NULL);
    
    unsigned char sig[65], msg[] = "OpenSSL Schnorr";
    
    BIGNUM *k = BN_new();
    BN_rand_range(k, order);
    EC_POINT *R = EC_POINT_new(g);
    EC_POINT_mul(g, R, k, NULL, NULL, NULL);
    EC_POINT_point2oct(g, R, POINT_CONVERSION_COMPRESSED, sig, 33, NULL);
    
    unsigned char Y[33];
    const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    EC_POINT_point2oct(g, pub, POINT_CONVERSION_COMPRESSED, Y, 33, NULL);
    
    SHA256_CTX sha; SHA256_Init(&sha);
    SHA256_Update(&sha, sig, 33); SHA256_Update(&sha, Y, 33);
    SHA256_Update(&sha, msg, 15);
    unsigned char c_hash[32]; SHA256_Final(c_hash, &sha);
    
    BIGNUM *c = BN_new(); BN_bin2bn(c_hash, 32, c); BN_mod(c, c, order, NULL);
    BIGNUM *s = BN_new(); BIGNUM *cx = BN_new();
    BN_mod_mul(cx, c, priv, order, NULL); BN_mod_add(s, k, cx, order, NULL);
    BN_bn2binpad(s, sig + 33, 32);
    printf("✅ PASS (sig=%02x%02x...)\n", sig[0], sig[1]);
    
    // Verify
    printf("Test 3: Verify...\n");
    EC_POINT *R2 = EC_POINT_new(g);
    EC_POINT_oct2point(g, R2, sig, 33, NULL);
    BIGNUM *s2 = BN_new(); BN_bin2bn(sig + 33, 32, s2);
    
    SHA256_Init(&sha); SHA256_Update(&sha, sig, 33);
    SHA256_Update(&sha, Y, 33); SHA256_Update(&sha, msg, 15);
    unsigned char c2_hash[32]; SHA256_Final(c2_hash, &sha);
    BIGNUM *c2 = BN_new(); BN_bin2bn(c2_hash, 32, c2); BN_mod(c2, c2, order, NULL);
    
    EC_POINT *sG = EC_POINT_new(g); EC_POINT_mul(g, sG, s2, NULL, NULL, NULL);
    EC_POINT *cY = EC_POINT_new(g); EC_POINT_mul(g, cY, NULL, pub, c2, NULL);
    EC_POINT *RcY = EC_POINT_new(g); EC_POINT_add(g, RcY, R2, cY, NULL);
    
    int result = (EC_POINT_cmp(g, sG, RcY, NULL) == 0);
    printf("%s\n", result ? "✅ PASS" : "❌ FAIL");
    
    EC_KEY_free(ec);
    return result ? 0 : 1;
}
