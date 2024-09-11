/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "lms_local.h"
#include "internal/refcount.h"

/**
 * @brief Create a new LMS_KEY object
 *
 * @returns The new LMS_KEY object on success, or NULL on malloc failure
 */
LMS_KEY *ossl_lms_key_new(void)
{
    return OPENSSL_zalloc(sizeof(LMS_KEY));
}

/**
 * @brief Destroy LMS_KEY object
 */
void ossl_lms_key_free(LMS_KEY *lmskey)
{
    LMS_PUB_KEY *pub;
    LMS_PRIV_KEY *priv;

    if (lmskey == NULL)
        return;

    ossl_lms_pubkey_cache_free(lmskey);
    pub = &lmskey->pub;
    if (pub->allocated)
        OPENSSL_free(pub->encoded);
    priv = &lmskey->priv;
    OPENSSL_clear_free(priv->data, priv->datalen);
    EVP_MD_CTX_free(lmskey->mdctx);
    OPENSSL_free(lmskey);
}

/**
 * @brief Calculate the public key associated with a node in a LMS tree.
 * Passing a |nodeid| of 1 returns the LMS root public key T[1].
 * All leaf keypairs are required in order to calculate this value, since each
 * node except for the leaf nodes involves calculating a hash of the 2 child
 * nodes (recursively).
 *
 * See RFC 8554 Section 5.3
 *
 * if (r >= 2^h)
 *     T[r] = H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
 * else
 *     T[r] = H(I||u32str(r)||u16str(D_INTR)||T[2r]||T[2r+1]
 *
 * OTS_PUB_HASH[i] is the OTS public key value (K) associated with the
 * OTS private key at position i. (where i = 0...2^h - 1).
 * It is calculated using Algorithm 1.
 * The values for T[r] are stored in a cache.
 *
 * @param key A LMS_KEY object containing parameters and keypair info for a LMS tree.
 * @nodeid tree node id (r) in the range (1...(2^(h+1) - 1))
 *         where the top node is 1, and the leaf nodes start from 2^h.
 *         The leaf nodes are OTS key pairs.
 * @out The returned public key of size n bytes.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lms_key_get_pubkey_from_nodeid(LMS_KEY *key,
                                        uint32_t nodeid, unsigned char *out)
{
    int ret;
    unsigned char buf[LMS_SIZE_I + 4 + 2];
    uint32_t n = key->lms_params->n;
    uint32_t leafoffset = 1 << key->lms_params->h;
    WPACKET pkt;
    size_t len;

    /* Exit early if we can retrieve from cache */
    if (ossl_lms_pubkey_cache_get(key, nodeid, out))
        return 1;

    /* I || u32str(nodeid) */
    if (!WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)
            || !WPACKET_memcpy(&pkt, key->Id, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, nodeid))
        goto err;

    /* Is it a leaf node ? */
    if (nodeid >= leafoffset) {
        uint32_t q = nodeid - leafoffset;
        unsigned char K[LMS_MAX_DIGEST_SIZE];

        /* out = H(I || nodeid || 0x8282 || K */
        ret = ossl_lm_ots_pubK_from_priv(key, q, K)
            && WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_LEAF)
            && WPACKET_get_total_written(&pkt, &len)
            && ossl_lms_hash(key->mdctx, buf, len, K, n, out);
    } else {
        unsigned char tlr[2 * LMS_MAX_DIGEST_SIZE];

        /*
         * out = H(I || nodeid || 0x8282 || T(Left Child) || T(Right Child)
         * Where T is a recursive call.
         */
        ret = WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_INTR)
            && WPACKET_get_total_written(&pkt, &len)
            && ossl_lms_key_get_pubkey_from_nodeid(key, 2 * nodeid, tlr)
            && ossl_lms_key_get_pubkey_from_nodeid(key, 2 * nodeid + 1, tlr + n)
            && ossl_lms_hash(key->mdctx, buf, len, tlr, 2 * n, out);
    }
    if (ret)
        ossl_lms_pubkey_cache_add(key, nodeid, out);
err:
    WPACKET_finish(&pkt);
    WPACKET_cleanup(&pkt);
    return ret;
}

/*
 * @brief Decode LMS public key data in XDR format into a LMS_KEY object.
 *
 * See RFC 8554 Algorithm 6: Steps 1 & 2.
 * The XDR format is lms_type[4] || ots_type[4] || I[16] || K[n]
 * Steps that involve checking the size of the public key data are
 * done indirectly by checking the return result of PACKET_get API's.
 * This function may be called multiple times when parsing a HSS signature.
 * It is also used by ossl_lms_pub_key_from_data() to load a public key.
 * This function only performs shallow copies.
 *
 * @param pkt The packet to read public key data in XDR format from.
 * @param lmskey The object to store the public key into
 * @return 1 on success or 0 otherwise.
 */
int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *lmskey)
{
    uint32_t lms_type;
    uint32_t ots_type;
    LMS_PUB_KEY *key = &lmskey->pub;

    key->encoded = (unsigned char *)pkt->curr;
    if (!PACKET_get_4_len(pkt, &lms_type))
        goto err;
    lmskey->lms_params = ossl_lms_params_get(lms_type);
    if (lmskey->lms_params == NULL
            || !PACKET_get_4_len(pkt, &ots_type))
        goto err;
    lmskey->ots_params = ossl_lm_ots_params_get(ots_type);
    if (lmskey->ots_params == NULL)
        goto err;

    /* The digest used must be the same */
    if (HASH_NOT_MATCHED(lmskey->ots_params, lmskey->lms_params)
            || !PACKET_get_bytes_shallow(pkt, &lmskey->Id, LMS_SIZE_I)
            || !PACKET_get_bytes_shallow(pkt, &key->K, lmskey->lms_params->n))
        goto err;
    key->encodedlen = pkt->curr - key->encoded;
    return 1;
err:
    return 0;
}

/**
 * @brief Determine the size of a LMS public key in XDR format.
 * It consists of lms_type[4] || ots_type[4] || I[16] + n
 *
 * @param lmskey The LMS key to retrieve the digest size 'n' from.
 * @returns The size of a XDR encoded LMS key.
 */
size_t ossl_lms_pubkey_encode_len(LMS_KEY *lmskey)
{
    return LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE + LMS_SIZE_I
        + lmskey->lms_params->n;
}

/**
 * @brief Write LMS public key object to a packet in XDR format.
 * It consists of lms_type[4] || ots_type[4] || I[16] || K[n]
 *
 * @param pkt The packet to write public key data to
 * @param lmskey The LMS_KEY containing a LMS public key.
 * @returns 1 if successfully written, or 0 otherwise
 */
int ossl_lms_pubkey_to_pkt(WPACKET *pkt, LMS_KEY *lmskey)
{
    return WPACKET_put_bytes_u32(pkt, lmskey->lms_params->lms_type)
        && WPACKET_put_bytes_u32(pkt, lmskey->ots_params->lm_ots_type)
        && WPACKET_memcpy(pkt, lmskey->Id, LMS_SIZE_I)
        && WPACKET_memcpy(pkt, lmskey->pub.K, lmskey->lms_params->n);
}

/*
 * @brief Decode LMS public key data in XDR format into a LMS_KEY object.
 * Used by a HSS public key decoder.
 * The XDR format is lms_type[4] || ots_type[4] || I[16] || K[n]
 *
 * @param pub byte array of public key data in XDR format.
 * @param publen is the size of |pub|.
 * @param lmskey The LMS_KEY object to store the public key into.
 * @returns 1 on success, or 0 otherwise. 0 is returned if either |pub| is
 * invalid or |publen| is not the correct size (i.e. trailing data is not allowed)
 */
int ossl_lms_pubkey_decode(const unsigned char *pub, size_t publen,
                           LMS_KEY *lmskey)
{
    PACKET pkt;
    LMS_PUB_KEY *pkey = &lmskey->pub;

    if (pkey->encoded != NULL && pkey->encodedlen != publen) {
        if (pkey->allocated) {
            OPENSSL_free(pkey->encoded);
            pkey->allocated = 0;
        }
        pkey->encodedlen = 0;
    }
    pkey->encoded = OPENSSL_memdup(pub, publen);
    if (pkey->encoded == NULL)
        return 0;

    if (!PACKET_buf_init(&pkt, pkey->encoded, publen)
            || !ossl_lms_pubkey_from_pkt(&pkt, lmskey)
            || (PACKET_remaining(&pkt) > 0))
        goto err;
    pkey->encodedlen = publen;
    pkey->allocated = 1;
    return 1;
err:
    OPENSSL_free(pkey->encoded);
    pkey->encoded = NULL;
    return 0;
}

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)

/**
 * @brief Initialize a LMS_KEY object.
 *
 * @param lmskey The LMS_KEY object to initialize.
 * @param lms_type The LMS type such as OSSL_LMS_TYPE_SHA256_N32_H5.
 * @param ots_type The OTS type such as OSSL_LM_OTS_TYPE_SHA256_N32_W1.
 * @param libctx The OSSL_LIB_CTX used to fetch the Digest algorithm.
 * @param propq The property query used to fetch the Digest algorithm.
 * @returns 1 on success or 0 otherwise.
 */
static int lms_key_init(LMS_KEY *lmskey, uint32_t lms_type, uint32_t ots_type,
                        OSSL_LIB_CTX *libctx, const char *propq)
{
    int ret = 0;
    const LM_OTS_PARAMS *prms = ossl_lm_ots_params_get(ots_type);
    const LMS_PARAMS *lprms = ossl_lms_params_get(lms_type);
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p = NULL;

    if (prms == NULL || lprms == NULL)
        return 0;

    lmskey->lms_params = lprms;
    lmskey->ots_params = prms;
    lmskey->libctx = libctx;

    if (!ossl_lms_pubkey_cache_new(lmskey))
        return 0;

    md = EVP_MD_fetch(libctx, lprms->digestname, propq);
    if (md == NULL)
        return 0;
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto err;
    if (strncmp(lprms->digestname, "SHAKE", 5) == 0) {
        size_t len = lprms->n;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &len);
        p = params;
    }
    if (EVP_DigestInit_ex2(mdctx, md, p) <= 0)
        goto err;
    ret = 1;
err:
    EVP_MD_free(md);
    if (ret == 1)
        lmskey->mdctx = mdctx;
    else
        EVP_MD_CTX_free(mdctx);
    return ret;
}

/**
 * @brief Generate a LMS_KEY key pair
 *
 * @param lms_type The LMS type such as OSSL_LMS_TYPE_SHA256_N32_H5
 * @param ots_type The OTS type such as OSSL_LM_OTS_TYPE_SHA256_N32_W1
 * @param libctx A OSSL_LIB_CTX object used for algorithm fetching
 * @param propq A property query used for algorithm fetching
 * @param parent The parent of this LMS_KEY. May be NULL.
 * @returns A newly generated LMS_KEY object on success, or NULL on failure.
 */
LMS_KEY *ossl_lms_key_gen(uint32_t lms_type, uint32_t ots_type,
                          OSSL_LIB_CTX *libctx, const char *propq,
                          LMS_KEY *parent)
{
    int ret;
    LMS_KEY *key;

    key = ossl_lms_key_new();
    if (key == NULL)
        return NULL;

    ret = lms_key_init(key, lms_type, ots_type, libctx, propq)
        && ossl_lms_key_reset(key, 0, parent)
        && ossl_lms_pubkey_compute(key);
    if (ret == 0) {
        ossl_lms_key_free(key);
        key = NULL;
    }
    return key;
}

/**
 * @brief Duplicate a LMS_PUB_KEY object
 * This function is called when ossl_hss_key_reserve() is used.
 *
 * @param dst The LMS_PUB_KEY to copy to.
 * @param src The LMS_PUB_KEY to copy from.
 * @param klen is the length of the public key (n)
 * @returns 1 on success, or 0 otherwise.
 */
static int lms_pubkey_copy(LMS_PUB_KEY *dst, const LMS_PUB_KEY *src,
                           uint32_t klen)
{
    if (src->encoded != NULL) {
        dst->encoded = OPENSSL_memdup(src->encoded, src->encodedlen);
        if (dst->encoded == NULL)
            return 0;
        dst->allocated = 1;
        dst->encodedlen = src->encodedlen;
        dst->K = dst->encoded + dst->encodedlen - klen;
    } else {
        dst->K = NULL;
        dst->encoded = NULL;
        dst->encodedlen = 0;
        dst->allocated = 0;
    }
    return 1;
}

/**
 * @brief Duplicate a LMS_PRIV_KEY object
 * This function is called when ossl_hss_key_reserve() is used.
 *
 * @param dst The LMS_PRIV_KEY to copy to
 * @param src The LMS_PRIV_KEY to copy from.
 * @param seedlen The size of the private key SEED value (n)
 * @returns 1 on success, or 0 otherwise.
 */
static int lms_privkey_copy(LMS_PRIV_KEY *dst, const LMS_PRIV_KEY *src,
                            uint32_t seedlen)
{
    if (src->data != NULL) {
        dst->data = OPENSSL_memdup(src->data, src->datalen);
        if (dst->data == NULL)
            return 0;
        dst->datalen = src->datalen;
        dst->seed = dst->data + dst->datalen - seedlen;
    } else {
        dst->data = NULL;
        dst->datalen = 0;
        dst->seed = NULL;
    }
    return 1;
}

/**
 * @brief Duplicate a LMS_KEY object
 * This function is called when ossl_hss_key_reserve() is used.
 *
 * @param src The LMS_KEY to copy.
 * @returns A new LMS_KEY object on success, or NULL otherwise.
 */
LMS_KEY *ossl_lms_key_deep_copy(const LMS_KEY *src)
{
    LMS_KEY *dst;
    uint32_t n;

    if (src == NULL)
        return NULL;
    dst = ossl_lms_key_new();
    if (dst == NULL)
        return NULL;
    dst->mdctx = EVP_MD_CTX_dup(src->mdctx);
    if (dst->mdctx == NULL)
        goto err;
    dst->libctx = src->libctx;
    dst->lms_params = src->lms_params;
    dst->ots_params = src->ots_params;
    dst->q = src->q;
    n = dst->lms_params->n;
    if (!ossl_lms_pubkey_cache_copy(dst, src)
            || !lms_pubkey_copy(&dst->pub, &src->pub, n)
            || !lms_privkey_copy(&dst->priv, &src->priv, n))
        goto err;
    if (dst->priv.data != NULL)
        dst->Id = dst->priv.data;
    else if (dst->pub.K != NULL)
        dst->Id = dst->pub.K - n;
    else
        dst->Id = NULL;

    return dst;
err:
    ossl_lms_key_free(dst);
    return NULL;
}

/*
 * @brief Generate a new active LMS tree private key.
 * Values for SEED and I are generated
 * (These are randomly generated for the root node, and are derived for the
 * children using the parents SEED and I).
 *
 * Note that the method used for generating the children's SEED and I,
 * is not part of RFC 8554.
 * It is used for ACVP testing, in order to have a deterministic sign,
 * See https://github.com/cisco/hash-sigs/blob/master/ACVP Definition.txt.
 * A FIPS hardware implementation would need to use a non deterministic method
 * for the children.
 *
 * The private key of a node i is calculated as.
 * x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED
 * (i is 0..p (ots private key index) & q = 0..2^h (leaf index))
 *
 * It fills in the priv->data buffer with the following data.
 *
 * I || u32str(q) || u16str(i) || u8str(0xff) || SEED
 * where q = 0, i = 0 to begin with.
 * The Hash H of this priv->data is a common operation
 * See ossl_lm_ots_get_private_xq()
 * priv->seed points to the SEED in this buffer.
 *
 * @param priv The LMS_Key to reset the private key in.
 * @param seedlen The size of the SEED generated (should be n)
 * @param nodeid The parents q index, used for deriving private key SEED and I
 * @param parent The parent LMS_KEY, used for deriving private key SEED and I.
 *               This is NULL for the root of the HSS tree.
 * @param libctx The OSSL_LIB_CTX object required for generating random bytes
 * @returns 1 on success or 0 otherwise.
 */
static int lms_privkey_reset(LMS_PRIV_KEY *priv, uint32_t seedlen,
                             uint32_t nodeid, LMS_KEY *parent,
                             OSSL_LIB_CTX *libctx)
{
    WPACKET pkt;
    uint8_t SEED[2 * LMS_MAX_DIGEST_SIZE]; /* truncated to LMS_SIZE_I */
    uint8_t *Id = SEED + seedlen;
    size_t datalen = LMS_OFFSET_SEED + seedlen;

    if (priv->data == NULL) {
        priv->data = OPENSSL_zalloc(datalen);
        if (priv->data == NULL)
            return 0;
        priv->datalen = datalen;
    }

    /*
     * According to SP800-208 Section 6.1, hardware implementations should
     * use an Approved RBG to generate this value.
     */
    if (parent == NULL) {
        /* Randomly generate SEED and I */
        if (RAND_priv_bytes_ex(libctx, SEED, seedlen + LMS_SIZE_I, 0) <= 0)
            goto err;
    } else {
        uint8_t buf[LMS_SIZE_I + LMS_SIZE_q + LMS_SIZE_DTAG + LMS_SIZE_j
                    + LMS_MAX_DIGEST_SIZE];
        size_t buflen;

        /*
         * Derive SEED and I from the parent seed.
         *
         * I = Hash(I || nodeid || 0xFFFF || 0xFF || parent->seed
         * SEED = Hash(I || nodeid || 0xFFFE || 0xFF || parent->seed
         */
        if (!WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)
                || !WPACKET_memcpy(&pkt, parent->Id, LMS_SIZE_I)
                || !WPACKET_put_bytes_u32(&pkt, nodeid) /* nodeid = q */
                || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_CHILD_I)
                || !WPACKET_put_bytes_u8(&pkt, 0xFF)
                || !WPACKET_memcpy(&pkt, parent->priv.seed, seedlen)
                || !WPACKET_get_total_written(&pkt, &buflen)
                || !ossl_lms_hash(parent->mdctx, buf, buflen, NULL, 0, Id)
                || !WPACKET_backward(&pkt, seedlen + LMS_SIZE_j + LMS_SIZE_DTAG)
                || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_CHILD_SEED)
                || !ossl_lms_hash(parent->mdctx, buf, buflen, NULL, 0, SEED)
                || !WPACKET_finish(&pkt))
            goto err;
    }
    /*
     * x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED
     * Where i = 0, q = 0.
     * Set priv->data to I || u32str(q) || u16str(i) || u8str(0xff) || SEED
     * and point priv->seed to the offset of SEED in priv->data
     */
    if (!WPACKET_init_static_len(&pkt, priv->data, priv->datalen, 0)
            || !WPACKET_memcpy(&pkt, Id, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, 0)  /* q */
            || !WPACKET_put_bytes_u16(&pkt, 0)  /* i */
            || !WPACKET_put_bytes_u8(&pkt, 0xFF)
            || ((priv->seed = WPACKET_get_curr(&pkt)) == NULL)
            || !WPACKET_memcpy(&pkt, SEED, seedlen)
            || !WPACKET_finish(&pkt))
        goto err;
    WPACKET_close(&pkt);
    return 1;
err:
    WPACKET_close(&pkt);
    OPENSSL_clear_free(priv->data, datalen);
    priv->data = NULL;
    priv->datalen = 0;
    return 0;
}

/**
 * @brief Clear the LMS trees root public key T[1], so that it will be recalculated
 */
static int lms_pubkey_reset(LMS_PUB_KEY *key)
{
    key->K = NULL;
    return 1;
}

/**
 * @brief Sets up a new LMS_KEY object.
 * This is used to create new active LMS trees, when the current active tree
 * becomes exhausted. This will generate a new private key SEED & I, and reset
 * the public key K.
 *
 * @param lmskey The LMS_KEY object to reset.
 * @param nodeid The parents q value is used when deriving private key SEED and I
 * @param parent The parent LMS_KEY is used for deriving private key SEED and I
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lms_key_reset(LMS_KEY *lmskey, int nodeid, LMS_KEY *parent)
{
    ossl_lms_pubkey_cache_flush(lmskey);

    if (!lms_privkey_reset(&lmskey->priv, lmskey->ots_params->n,
                           nodeid, parent, lmskey->libctx))
        return 0;
    if (!lms_pubkey_reset(&lmskey->pub))
        return 0;
    lmskey->Id = lmskey->priv.data;
    lmskey->q = 0;
    return 1;
}

/**
 * @returns The number of bytes remaining in a fixed size WPACKET
 */
static int WPACKET_remaining(WPACKET *pkt)
{
    return pkt->maxsize - pkt->curr;
}

/**
 * @brief Compute the LMS public key.
 * See RFC 8554 Section 5.3 LMS public Key
 *
 * Create an encoded LMS public key which consists of
 * u32str(lmstype) || u32str(otstype) || I || K
 *
 * Where K = T[1] is calculated by calling ossl_lms_key_get_pubkey_from_nodeid()
 *
 * @param lmskey A LMS_KEY object containing OTS keypairs in its leaf nodes.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lms_pubkey_compute(LMS_KEY *lmskey)
{
    int ret = 0;
    LMS_PUB_KEY *pub = &lmskey->pub;
    const LM_OTS_PARAMS *prms = lmskey->ots_params;
    uint8_t n = prms->n;
    WPACKET pkt;

    /* Allocate a buffer for the encoded public key once */
    if (pub->encoded == NULL) {
        pub->encodedlen = LMS_SIZE_PUB_LMS_TYPE + LMS_SIZE_PUB_OTS_TYPE
            + LMS_SIZE_I + n;
        pub->encoded = OPENSSL_malloc(pub->encodedlen);
        if (pub->encoded == NULL)
            return 0;
        pub->allocated = 1;
    }
    if (!WPACKET_init_static_len(&pkt, pub->encoded, pub->encodedlen, 0))
        return 0;

    /* Only do this if the public key is not already cached */
    if (pub->K == NULL) {
        unsigned char *pK = NULL;
        unsigned char K[LMS_MAX_DIGEST_SIZE];

        /* Do a recursive call to calculate the public key K */
        if (!ossl_lms_key_get_pubkey_from_nodeid(lmskey, 1, K))
            goto err;

        /* XDR encode the public key into pub->encoded */
        if (!WPACKET_put_bytes_u32(&pkt, lmskey->lms_params->lms_type)
                || !WPACKET_put_bytes_u32(&pkt, prms->lm_ots_type)
                || !WPACKET_memcpy(&pkt, lmskey->Id, LMS_SIZE_I))
            goto err;

        pK = WPACKET_get_curr(&pkt);
        if (!WPACKET_memcpy(&pkt, K, n)
                || WPACKET_remaining(&pkt) > 0)
            goto err;
        pub->K = pK;
    }
    ret = 1;
err:
    WPACKET_finish(&pkt);
    return ret;
}

#endif /* OPENSSL_NO_HSS_GEN */
