#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

int schnorr_sign(const unsigned char *msg, size_t msg_len,
                  const unsigned char *priv_key,
                  unsigned char *sig, size_t *sig_len)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) { EC_KEY_free(ec); return 0; }

    BIGNUM *priv = BN_new();
    BN_bin2bn(priv_key, 32, priv);
    EC_KEY_set_private_key(ec, priv);

    EC_POINT *pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, bn_ctx);
    EC_KEY_set_public_key(ec, pub);

    BIGNUM *k = BN_new();
    BN_rand_range(k, order);

    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, k, NULL, NULL, bn_ctx);

    unsigned char hash[32];
    SHA256_CTX sha;
    SHA256_Init(&sha);

    unsigned char R_bytes[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, R_bytes, 33, bn_ctx);
    SHA256_Update(&sha, R_bytes, 33);

    unsigned char Y_bytes[33];
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED, Y_bytes, 33, bn_ctx);
    SHA256_Update(&sha, Y_bytes, 33);

    SHA256_Update(&sha, msg, msg_len);
    SHA256_Final(hash, &sha);

    BIGNUM *c = BN_new();
    BN_bin2bn(hash, 32, c);
    BN_mod(c, c, order, bn_ctx);

    BIGNUM *s = BN_new();
    BIGNUM *c_priv = BN_new();
    BN_mod_mul(c_priv, c, priv, order, bn_ctx);
    BN_mod_add(s, k, c_priv, order, bn_ctx);

    int order_bytes = BN_num_bytes(order);
    unsigned char *ptr = sig;
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, ptr, 33, bn_ctx);
    ptr += 33;
    BN_bn2binpad(s, ptr, order_bytes);
    *sig_len = 33 + order_bytes;

    BN_free(c_priv);
    BN_free(s);
    BN_free(c);
    EC_POINT_free(R);
    BN_free(k);
    BN_free(priv);
    EC_POINT_free(pub);
    EC_KEY_free(ec);
    BN_CTX_free(bn_ctx);

    return 1;
}

int schnorr_verify(const unsigned char *msg, size_t msg_len,
                    const unsigned char *pub_key,
                    const unsigned char *sig, size_t sig_len)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) { EC_KEY_free(ec); return 0; }

    EC_POINT *Y = EC_POINT_new(group);
    EC_POINT_oct2point(group, Y, pub_key, 33, bn_ctx);
    EC_KEY_set_public_key(ec, Y);

    int order_bytes = BN_num_bytes(order);

    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_oct2point(group, R, sig, 33, bn_ctx);

    BIGNUM *s = BN_new();
    BN_bin2bn(sig + 33, order_bytes, s);

    unsigned char hash[32];
    SHA256_CTX sha;
    SHA256_Init(&sha);

    unsigned char R_bytes[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, R_bytes, 33, bn_ctx);
    SHA256_Update(&sha, R_bytes, 33);

    unsigned char Y_bytes[33];
    EC_POINT_point2oct(group, Y, POINT_CONVERSION_COMPRESSED, Y_bytes, 33, bn_ctx);
    SHA256_Update(&sha, Y_bytes, 33);

    SHA256_Update(&sha, msg, msg_len);
    SHA256_Final(hash, &sha);

    BIGNUM *c = BN_new();
    BN_bin2bn(hash, 32, c);
    BN_mod(c, c, order, bn_ctx);

    EC_POINT *sG = EC_POINT_new(group);
    EC_POINT *cY = EC_POINT_new(group);
    EC_POINT *RcY = EC_POINT_new(group);

    EC_POINT_mul(group, sG, s, NULL, NULL, bn_ctx);
    EC_POINT_mul(group, cY, NULL, Y, c, bn_ctx);
    EC_POINT_add(group, RcY, R, cY, bn_ctx);

    int result = (EC_POINT_cmp(group, sG, RcY, bn_ctx) == 0);

    EC_POINT_free(RcY);
    EC_POINT_free(cY);
    EC_POINT_free(sG);
    BN_free(c);
    BN_free(s);
    EC_POINT_free(R);
    EC_POINT_free(Y);
    EC_KEY_free(ec);
    BN_CTX_free(bn_ctx);

    return result;
}

int main()
{
    const unsigned char msg[] = "Schnorr Test";
    unsigned char priv[32];
    unsigned char pub[33];
    unsigned char sig[128];
    size_t sig_len;

    RAND_bytes(priv, 32);

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *priv_bn = BN_new();
    BN_bin2bn(priv, 32, priv_bn);
    EC_POINT *pub_pt = EC_POINT_new(group);
    EC_POINT_mul(group, pub_pt, priv_bn, NULL, NULL, bn_ctx);
    EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_COMPRESSED, pub, 33, bn_ctx);
    BN_free(priv_bn);
    EC_POINT_free(pub_pt);
    EC_KEY_free(ec);
    BN_CTX_free(bn_ctx);

    printf("Signing...\n");
    schnorr_sign(msg, strlen((char*)msg), priv, sig, &sig_len);

    printf("Verifying...\n");
    int r = schnorr_verify(msg, strlen((char*)msg), pub, sig, sig_len);
    printf(r ? "PASS\n" : "FAIL\n");

    return 0;
}
