/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h" /* EC_POINT_mul_fn() */
#include "crypto/bn.h" /* bn_acquire_ossl_fn(), bn_release() */
#include "crypto/fn.h"
#include "crypto/fn_intern.h" /* ossl_fn_ctx_{max,add}_size() */
#include "internal/numbers.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>

/*
 * [SM2 Signature Scheme]
 * (https://datatracker.ietf.org/doc/html/rfc8998#section-3.2.1)
 *
 * If either a client or a server needs to verify the peer's SM2 certificate
 * contained in the Certificate message, then the following ASCII string value
 * MUST be used as the SM2 identifier according to [GMT.0009-2012]:
 *
 * 1234567812345678
 */
static const uint8_t default_sm2_id[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

int ossl_sm2_compute_z_digest(uint8_t *out,
    const EVP_MD *digest,
    const uint8_t *id,
    size_t id_len,
    const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pubkey = EC_KEY_get0_public_key(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    /* SM2 Signatures require a public key, check for it */
    if (pubkey == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }
    ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id == NULL) {
        id = default_sm2_id;
        id_len = sizeof(default_sm2_id);
    }

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        ERR_raise(ERR_LIB_SM2, SM2_R_ID_TOO_LARGE);
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL)
        goto done;

    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
            EC_GROUP_get0_generator(group),
            xG, yG, ctx)
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
            pubkey,
            xA, yA, ctx)
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EVP_DigestFinal(hash, out, NULL)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

done:
    OPENSSL_free(buf);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
    const EC_KEY *key,
    const uint8_t *id,
    const size_t id_len,
    const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_get_size(digest);
    uint8_t *z = NULL;
    BIGNUM *e = NULL;
    EVP_MD *fetched_digest = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);
    const char *propq = ossl_ec_key_get0_propq(key);

    if (md_size <= 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_DIGEST);
        goto done;
    }
    if (hash == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    z = OPENSSL_zalloc(md_size);
    if (z == NULL)
        goto done;

    fetched_digest = EVP_MD_fetch(libctx, EVP_MD_get0_name(digest), propq);
    if (fetched_digest == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!ossl_sm2_compute_z_digest(z, fetched_digest, id, id_len, key)) {
        /* SM2err already called */
        goto done;
    }

    if (!EVP_DigestInit(hash, fetched_digest)
        || !EVP_DigestUpdate(hash, z, md_size)
        || !EVP_DigestUpdate(hash, msg, msg_len)
        /* reuse z buffer to hold H(Z || M) */
        || !EVP_DigestFinal(hash, z, NULL)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    e = BN_bin2bn(z, md_size, NULL);
    if (e == NULL)
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);

done:
    EVP_MD_free(fetched_digest);
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}

static ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e)
{
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    ECDSA_SIG *sig = NULL;
    EC_POINT *kG = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    BIGNUM *x1 = NULL;
    OSSL_FN_CTX *fnctx = NULL;
    const void *token = NULL;
    const OSSL_FN *order_fn = NULL;
    OSSL_FN *k = NULL;
    OSSL_FN *rk = NULL;
    OSSL_FN *tmp = NULL;
    OSSL_FN *sf = NULL;
    OSSL_FN *rf = NULL;
    OSSL_FN *dAf = NULL;
    OSSL_FN *one = NULL;
    OSSL_FN *s_acq = NULL;
    int nlimbs;
    size_t need;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    if (dA == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY);
        goto done;
    }
    kG = EC_POINT_new(group);
    if (kG == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }
    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    BN_CTX_start(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_new();
    s = BN_new();

    if (r == NULL || s == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    /*
     * The order is public and stays a BIGNUM; only its OSSL_FN view is
     * needed, which is read-only and so needs no bn_release().
     */
    nlimbs = bn_get_top(order);
    if ((order_fn = bn_get_ossl_fn(order)) == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    /*
     * Size the arena for the temporaries below plus the widest of the nested
     * modular operations.  Every operand handed to those is exactly nlimbs
     * wide, and order_fn is at least that wide (a BIGNUM's dmax is never
     * below its top), so modelling them all as order_fn is an upper bound.
     */
    need = ossl_fn_ctx_max_size(
        ossl_fn_ctx_max_size(
            OSSL_FN_mod_inverse_ctx_size(order_fn, order_fn, order_fn),
            OSSL_FN_mod_mul_ctx_size(order_fn, order_fn, order_fn, order_fn)),
        OSSL_FN_mod_sub_ctx_size(order_fn, order_fn, order_fn, order_fn));
    /*
     * Seven temporaries; rk is one limb wider, see below.
     * The order of the SM2 curve group is fixed, so we don't have to worry
     * about overflow.
     */
    need = ossl_fn_ctx_add_size(need,
        OSSL_FN_CTX_size(1, 7, 7 * (size_t)nlimbs + 1));
    if (need == 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    /* k and everything derived from it are secret, hence the secure arena. */
    fnctx = OSSL_FN_CTX_secure_new_size(libctx, need);
    if (fnctx == NULL || (token = OSSL_FN_CTX_start(fnctx)) == NULL)
        goto done;

    /*
     * rk holds r + k unreduced, and both are below the order, so it needs one
     * limb more than the order to be sure of not truncating the sum.
     */
    if ((k = OSSL_FN_CTX_get_limbs(fnctx, nlimbs)) == NULL
        || (rk = OSSL_FN_CTX_get_limbs(fnctx, nlimbs + 1)) == NULL
        || (tmp = OSSL_FN_CTX_get_limbs(fnctx, nlimbs)) == NULL
        || (sf = OSSL_FN_CTX_get_limbs(fnctx, nlimbs)) == NULL
        || (rf = OSSL_FN_CTX_get_limbs(fnctx, nlimbs)) == NULL
        || (dAf = OSSL_FN_CTX_get_limbs(fnctx, nlimbs)) == NULL
        || (one = OSSL_FN_CTX_get_limbs(fnctx, nlimbs)) == NULL)
        goto done;

    /*
     * dA is below the order, so nlimbs holds it and the truncating copy drops
     * nothing.  Copying it into an arena temporary rather than using the
     * private key BIGNUM's own OSSL_FN view keeps every operand exactly
     * nlimbs wide, which is what the sizing above relies on.
     */
    if (OSSL_FN_copy_truncate(dAf, bn_get_ossl_fn(dA)) == NULL
        || !OSSL_FN_one(one))
        goto done;

    /*
     * A3: Generate a random number k in [1,n-1] using random number generators;
     * A4: Compute (x1,y1)=[k]G, and convert the type of data x1 to be integer
     *     as specified in clause 4.2.8 of GM/T 0003.1-2012;
     * A5: Compute r=(e+x1) mod n. If r=0 or r+k=n, then go to A3;
     * A6: Compute s=(1/(1+dA)*(k-r*dA)) mod n. If s=0, then go to A3;
     * A7: Convert the type of data (r,s) to be bit strings according to the details
     *     in clause 4.2.2 of GM/T 0003.1-2012. Then the signature of message M is (r,s).
     */
    for (;;) {
        if (!OSSL_FN_priv_rand_range(k, order_fn, 0, libctx))
            goto done;

        /*
         * x1 and hence r are public: r is half the signature, and x1 is
         * recoverable from it.  Only k needs protecting here, which is why
         * the multiplication goes through EC_POINT_mul_fn().
         */
        if (!EC_POINT_mul_fn(group, kG, k, NULL, NULL)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, NULL,
                ctx)
            || !BN_mod_add(r, e, x1, order, ctx)) {
            ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        /* try again if r == 0 or r+k == n */
        if (BN_is_zero(r))
            continue;

        /* r is below the order, so this copy drops nothing either. */
        if (OSSL_FN_copy_truncate(rf, bn_get_ossl_fn(r)) == NULL
            || !OSSL_FN_add(rk, rf, k))
            goto done;

        if (OSSL_FN_cmp(rk, order_fn) == 0)
            continue;

        /*
         * OSSL_FN is unsigned, so the k - r*dA of A6 is a modular
         * subtraction here.  The BIGNUM version lets BN_sub go negative and
         * leaves it to BN_mod_mul to reduce; both land on the same residue.
         *
         * 1 + dA is an OSSL_FN_add against a one rather than an
         * OSSL_FN_add_word, because add_word stops as soon as the carry is
         * exhausted and so would run for a length that depends on dA.
         *
         * TODO(FIXNUM): OSSL_FN_mod_inverse() is not constant-time - by its
         * own account in crypto/fn/fn_mod_inv.c the iteration count reveals
         * the operand's magnitude, and the operand here is 1 + dA.  The
         * BIGNUM version reached ossl_ec_group_do_inverse_ord(), which
         * avoids that with Fermat's little theorem.  To be revisited once
         * crypto/fn grows a constant-time inverse.
         */
        if (!OSSL_FN_add(sf, dAf, one)
            || !OSSL_FN_mod_inverse(sf, sf, order_fn, fnctx)
            || !OSSL_FN_mod_mul(tmp, dAf, rf, order_fn, fnctx)
            || !OSSL_FN_mod_sub(tmp, k, tmp, order_fn, fnctx))
            goto done;

        /*
         * s is the other half of the signature and so is public from here
         * on.  It is computed straight into the OSSL_FN of its BIGNUM, so
         * the secret factors never have to be handed over as a BIGNUM.
         */
        if ((s_acq = bn_acquire_ossl_fn(s, nlimbs)) == NULL) {
            ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
            goto done;
        }
        if (!OSSL_FN_mod_mul(s_acq, sf, tmp, order_fn, fnctx)) {
            bn_release(s, nlimbs);
            s_acq = NULL;
            goto done;
        }
        bn_release(s, nlimbs);
        s_acq = NULL;

        /* try again if s == 0 */
        if (BN_is_zero(s))
            continue;

        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            ERR_raise(ERR_LIB_SM2, ERR_R_ECDSA_LIB);
            goto done;
        }

        /* takes ownership of r and s */
        ECDSA_SIG_set0(sig, r, s);
        break;
    }

done:
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
    }

    OSSL_FN_CTX_end(fnctx, token);
    OSSL_FN_CTX_free(fnctx);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    return sig;
}

static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig,
    const BIGNUM *e)
{
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    EC_POINT *pt = NULL;
    BIGNUM *t = NULL;
    BIGNUM *x1 = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    pt = EC_POINT_new(group);
    if (pt == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    /*
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: verify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA || M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
     */

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_cmp(r, BN_value_one()) < 0
        || BN_cmp(s, BN_value_one()) < 0
        || BN_cmp(order, r) <= 0
        || BN_cmp(order, s) <= 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!BN_mod_add(t, r, s, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    if (BN_is_zero(t)) {
        ERR_raise(ERR_LIB_SM2, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx)
        || !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    if (!BN_mod_add(t, e, x1, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    if (BN_cmp(r, t) == 0)
        ret = 1;

done:
    EC_POINT_free(pt);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

ECDSA_SIG *ossl_sm2_do_sign(const EC_KEY *key,
    const EVP_MD *digest,
    const uint8_t *id,
    const size_t id_len,
    const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    sig = sm2_sig_gen(key, e);

done:
    BN_free(e);
    return sig;
}

int ossl_sm2_do_verify(const EC_KEY *key,
    const EVP_MD *digest,
    const ECDSA_SIG *sig,
    const uint8_t *id,
    const size_t id_len,
    const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    int ret = 0;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    ret = sm2_sig_verify(key, sig, e);

done:
    BN_free(e);
    return ret;
}

int ossl_sm2_internal_sign(const unsigned char *dgst, int dgstlen,
    unsigned char *sig, unsigned int *siglen,
    EC_KEY *eckey)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *s = NULL;
    int sigleni;
    int ret = -1;

    if (sig == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    s = sm2_sig_gen(eckey, e);
    if (s == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    sigleni = i2d_ECDSA_SIG(s, &sig);
    if (sigleni < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *siglen = (unsigned int)sigleni;

    ret = 1;

done:
    ECDSA_SIG_free(s);
    BN_free(e);
    return ret;
}

int ossl_sm2_internal_verify(const unsigned char *dgst, int dgstlen,
    const unsigned char *sig, int sig_len,
    EC_KEY *eckey)
{
    ECDSA_SIG *s = NULL;
    BIGNUM *e = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_ECDSA_LIB);
        goto done;
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto done;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sig, der, derlen) != 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto done;
    }

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    ret = sm2_sig_verify(eckey, s, e);

done:
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    return ret;
}
