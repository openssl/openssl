#if __has_include(<oqs/oqs.h>)
/*
 * Schnorr+Falcon-1024 Hybrid Signature Provider
 * Classical: Schnorr secp256k1 + Post-Quantum: Falcon-1024 NIST Level 5
 * Composite: schnorr_sig || falcon_sig
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#endif
#include <string.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/schnorr_falcon.h"

/* ===== Schnorr RFC 8235 over secp256k1 ===== */
static int schnorr_sign_raw(const unsigned char *msg, size_t msg_len,
                             const BIGNUM *priv, unsigned char *sig, size_t *sig_len)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    const BIGNUM *n = EC_GROUP_get0_order(g);
    BN_CTX *bn = BN_CTX_new();
    if (!bn) { EC_KEY_free(ec); return 0; }
    EC_KEY_set_private_key(ec, priv);
    EC_POINT *Y = EC_POINT_new(g);
    EC_POINT_mul(g, Y, priv, NULL, NULL, bn);
    BIGNUM *k = BN_new(); BN_rand_range(k, n);
    EC_POINT *R = EC_POINT_new(g);
    EC_POINT_mul(g, R, k, NULL, NULL, bn);
    unsigned char hash[32], Rb[33], Yb[33];
    SHA256_CTX sha; SHA256_Init(&sha);
    EC_POINT_point2oct(g, R, POINT_CONVERSION_COMPRESSED, Rb, 33, bn);
    SHA256_Update(&sha, Rb, 33);
    EC_POINT_point2oct(g, Y, POINT_CONVERSION_COMPRESSED, Yb, 33, bn);
    SHA256_Update(&sha, Yb, 33);
    SHA256_Update(&sha, msg, msg_len);
    SHA256_Final(hash, &sha);
    BIGNUM *c = BN_new(); BN_bin2bn(hash, 32, c); BN_mod(c, c, n, bn);
    BIGNUM *s = BN_new(), *cx = BN_new();
    BN_mod_mul(cx, c, priv, n, bn);
    BN_mod_add(s, k, cx, n, bn);
    int nb = BN_num_bytes(n);
    EC_POINT_point2oct(g, R, POINT_CONVERSION_COMPRESSED, sig, 33, bn);
    BN_bn2binpad(s, sig + 33, nb);
    *sig_len = 33 + nb;
    BN_free(cx); BN_free(s); BN_free(c);
    EC_POINT_free(R); BN_free(k); EC_POINT_free(Y);
    EC_KEY_free(ec); BN_CTX_free(bn);
    return 1;
}

static int schnorr_verify_raw(const unsigned char *msg, size_t msg_len,
                               const EC_POINT *Y, const unsigned char *sig, size_t sig_len)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return 0;
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    const BIGNUM *n = EC_GROUP_get0_order(g);
    BN_CTX *bn = BN_CTX_new();
    if (!bn) { EC_KEY_free(ec); return 0; }
    int nb = BN_num_bytes(n);
    if (sig_len < (size_t)(33 + nb)) { BN_CTX_free(bn); EC_KEY_free(ec); return 0; }
    EC_POINT *R = EC_POINT_new(g);
    EC_POINT_oct2point(g, R, sig, 33, bn);
    BIGNUM *s = BN_new(); BN_bin2bn(sig + 33, nb, s);
    unsigned char hash[32], Rb[33], Yb[33];
    SHA256_CTX sha; SHA256_Init(&sha);
    EC_POINT_point2oct(g, R, POINT_CONVERSION_COMPRESSED, Rb, 33, bn);
    SHA256_Update(&sha, Rb, 33);
    EC_POINT_point2oct(g, Y, POINT_CONVERSION_COMPRESSED, Yb, 33, bn);
    SHA256_Update(&sha, Yb, 33);
    SHA256_Update(&sha, msg, msg_len);
    SHA256_Final(hash, &sha);
    BIGNUM *c = BN_new(); BN_bin2bn(hash, 32, c); BN_mod(c, c, n, bn);
    EC_POINT *sG = EC_POINT_new(g), *cY = EC_POINT_new(g), *RcY = EC_POINT_new(g);
    EC_POINT_mul(g, sG, s, NULL, NULL, bn);
    EC_POINT_mul(g, cY, NULL, Y, c, bn);
    EC_POINT_add(g, RcY, R, cY, bn);
    int ok = (EC_POINT_cmp(g, sG, RcY, bn) == 0);
    EC_POINT_free(RcY); EC_POINT_free(cY); EC_POINT_free(sG);
    BN_free(c); BN_free(s); EC_POINT_free(R);
    BN_CTX_free(bn); EC_KEY_free(ec);
    return ok;
}

/* ===== Provider Context ===== */
typedef struct { OSSL_LIB_CTX *libctx; SCHNORR_FALCON_KEY *key; char *propq; int op; } PROV_SF_CTX;

static void *sf_newctx(void *provctx, const char *propq) {
    PROV_SF_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (c) { c->libctx = PROV_LIBCTX_OF(provctx); if (propq) c->propq = OPENSSL_strdup(propq); }
    return c;
}
static void sf_freectx(void *v) { PROV_SF_CTX *c = v; OPENSSL_free(c->propq); OPENSSL_free(c); }
static int sf_init(void *v, void *k, const OSSL_PARAM p[], int op) {
    PROV_SF_CTX *c = v;
    if (!c || !k) return 0;
    c->key = k; c->op = op; return 1;
}
static int sf_sign_init(void *v, void *k, const OSSL_PARAM p[]) { return sf_init(v,k,p,EVP_PKEY_OP_SIGN); }
static int sf_verify_init(void *v, void *k, const OSSL_PARAM p[]) { return sf_init(v,k,p,EVP_PKEY_OP_VERIFY); }
static int sf_digest_init(void *v, const char *md, void *k, const OSSL_PARAM p[]) {
    if (md && md[0]) return 0;
    return sf_init(v,k,p,0);
}

/* DECLARED: Signature process aligns — NULL query gets true length */
static int sf_sign(void *v, unsigned char *sig, size_t *sl, size_t ss,
                    const unsigned char *tbs, size_t tl) {
    PROV_SF_CTX *c = v; SCHNORR_FALCON_KEY *k = c->key;
    if (!k || !k->schnorr_key || !k->falcon_privkey) return 0;
    
    unsigned char schnorr_sig[128]; size_t schnorr_len = sizeof(schnorr_sig);
    if (!schnorr_sign_raw(tbs, tl, EC_KEY_get0_private_key(k->schnorr_key), schnorr_sig, &schnorr_len)) return 0;
    
    /* Always compute actual Falcon signature to get true length */
    unsigned char *falcon_buf = OPENSSL_malloc(OQS_SIG_falcon_1024_length_signature);
    size_t falcon_len = OQS_SIG_falcon_1024_length_signature;
    if (OQS_SIG_falcon_1024_sign(falcon_buf, &falcon_len, tbs, tl, k->falcon_privkey) != OQS_SUCCESS) {
        OPENSSL_free(falcon_buf); return 0;
    }
    
    size_t total = schnorr_len + falcon_len;
    
    if (sig == NULL || ss == 0) {
        /* NULL query — return the TRUE length */
        *sl = total;
        OPENSSL_free(falcon_buf);
        return 1;
    }
    
    if (ss < total) { OPENSSL_free(falcon_buf); return 0; }
    
    /* Assemble composite signature */
    memcpy(sig, schnorr_sig, schnorr_len);
    memcpy(sig + schnorr_len, falcon_buf, falcon_len);
    *sl = total;
    
    OPENSSL_free(falcon_buf);
    return 1;
}

/* DECLARED: Verify process uses correct offsets */
static int sf_verify(void *v, const unsigned char *sig, size_t sl,
                      const unsigned char *tbs, size_t tl) {
    PROV_SF_CTX *c = v; SCHNORR_FALCON_KEY *k = c->key;
    if (!k || !k->schnorr_key || !k->falcon_pubkey) return 0;
    size_t schnorr_len = 65;
    if (sl < schnorr_len + 1) return 0;
    const EC_POINT *pk = EC_KEY_get0_public_key(k->schnorr_key);
    if (!pk) return 0;
    if (!schnorr_verify_raw(tbs, tl, pk, sig, schnorr_len)) return 0;
    return (OQS_SIG_falcon_1024_verify(tbs, tl, sig+schnorr_len, sl-schnorr_len, k->falcon_pubkey) == OQS_SUCCESS);
}

static int sf_digest_sign(void *v, unsigned char *sig, size_t *sl, size_t ss,
                           const unsigned char *tbs, size_t tl)
{ return sf_sign(v, sig, sl, ss, tbs, tl); }

static int sf_digest_verify(void *v, const unsigned char *sig, size_t sl,
                             const unsigned char *tbs, size_t tl)
{ return sf_verify(v, sig, sl, tbs, tl); }

const OSSL_DISPATCH ossl_schnorr_falcon_1024_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sf_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sf_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sf_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sf_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sf_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sf_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sf_digest_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))sf_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))sf_digest_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))sf_digest_verify },
    OSSL_DISPATCH_END
};
#endif /* HAVE_LIBOQS */
