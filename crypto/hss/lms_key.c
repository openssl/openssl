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
#include "lms_local.h"
#include "internal/refcount.h"

LMS_KEY *ossl_lms_key_new(void)
{
    return OPENSSL_zalloc(sizeof(LMS_KEY));
}

void ossl_lms_key_free(LMS_KEY *lmskey)
{
    LMS_PUB_KEY *pub;
    LMS_PRIV_KEY *priv;

    if (lmskey == NULL)
        return;

    ossl_lms_key_node_cache_final(lmskey);
    pub = &lmskey->pub;
    if (pub->allocated)
        OPENSSL_free(pub->encoded);
    priv = &lmskey->priv;
    OPENSSL_clear_free(priv->data, priv->datalen);
    OPENSSL_free(lmskey);
}

static int ossl_lms_key_init(LMS_KEY *lmskey,
                             uint32_t lms_type, uint32_t ots_type,
                             OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    const LM_OTS_PARAMS *prms = ossl_lm_ots_params_get(ots_type);
    const LMS_PARAMS *lprms = ossl_lms_params_get(lms_type);
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if (prms == NULL || lprms == NULL)
        return 0;

    lmskey->lms_params = lprms;
    lmskey->ots_params = prms;
    lmskey->libctx = libctx;

    if (!ossl_lms_key_node_cache_init(lmskey))
        return 0;

    md = EVP_MD_fetch(libctx, lprms->digestname, NULL);
    if (md == NULL)
        return 0;
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto err;
    if (EVP_DigestInit_ex2(mdctx, md, NULL) <= 0)
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

static int ossl_lms_pub_key_copy(const LMS_PUB_KEY *src, uint32_t klen,
                                 LMS_PUB_KEY *dst)
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

static int ossl_lms_priv_key_copy(const LMS_PRIV_KEY *src, uint32_t seedlen,
                                  LMS_PRIV_KEY *dst)
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

static int ossl_lms_priv_key_reset(LMS_PRIV_KEY *priv, uint32_t seedlen,
                                   uint32_t nodeid,
                                   OSSL_LIB_CTX *libctx, LMS_KEY *parent)
{
    WPACKET pkt;
    uint8_t I[LMS_MAX_DIGEST_SIZE]; /* truncated to LMS_SIZE_I */
    uint8_t SEED[LMS_MAX_DIGEST_SIZE];
    size_t datalen = LMS_OFFSET_SEED + seedlen;

    if (priv->data == NULL) {
        priv->data = OPENSSL_zalloc(datalen);
        if (priv->data == NULL)
            return 0;
        priv->datalen = datalen;
    }

    if (parent == NULL) {
        if (RAND_priv_bytes_ex(libctx, SEED, seedlen, 0) <= 0
                || RAND_priv_bytes_ex(libctx, I, LMS_SIZE_I, 0) <= 0)
            goto err;
    } else {
        uint8_t buf[LMS_SIZE_I + LMS_SIZE_q + LMS_SIZE_DTAG + LMS_SIZE_j + LMS_MAX_DIGEST_SIZE];
        size_t buflen;
        unsigned char *cur;

        if (!WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)
                || !WPACKET_memcpy(&pkt, parent->I, LMS_SIZE_I)
                || !WPACKET_put_bytes_u32(&pkt, nodeid)
                || ((cur = WPACKET_get_curr(&pkt)) == NULL)
                || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_CHILD_I)
                || !WPACKET_put_bytes_u8(&pkt, 0xFF)
                || !WPACKET_memcpy(&pkt, parent->priv.seed, seedlen)
                || !WPACKET_get_total_written(&pkt, &buflen)
                || !ossl_lms_hash(parent->mdctx, buf, buflen, NULL, 0, I)
                || !WPACKET_backward(&pkt, seedlen + LMS_SIZE_j + LMS_SIZE_DTAG)
                || !WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_CHILD_SEED)
                || !ossl_lms_hash(parent->mdctx, buf, buflen, NULL, 0, SEED))
                goto err;
    }
    if (!WPACKET_init_static_len(&pkt, priv->data, priv->datalen, 0)
            || !WPACKET_memcpy(&pkt, I, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, 0)
            || !WPACKET_put_bytes_u16(&pkt, 0)
            || !WPACKET_put_bytes_u8(&pkt, 0xFF)
            || ((priv->seed = WPACKET_get_curr(&pkt)) == NULL)
            || !WPACKET_memcpy(&pkt, SEED, seedlen))
        goto err;
    return 1;
err:
    OPENSSL_clear_free(priv->data, datalen);
    priv->data = NULL;
    priv->datalen = 0;
    return 0;
}

static int ossl_lms_pub_key_reset(LMS_PUB_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->K = NULL;
    return 1;
}

int ossl_lms_key_reset(LMS_KEY *lmskey, int nodeid, LMS_KEY *parent)
{
    ossl_lms_key_node_cache_flush(lmskey);

    if (!ossl_lms_priv_key_reset(&lmskey->priv, lmskey->ots_params->n,
                                 nodeid, lmskey->libctx, parent))
        return 0;
    if (!ossl_lms_pub_key_reset(&lmskey->pub, lmskey->libctx))
        return 0;
    lmskey->I = lmskey->priv.data;
    lmskey->q = 0;
    return 1;
}

/*
 * Recursive call to calculate the public key associated with a node.
 * Passing a nodeid of 1 returns the LMS root public key T[1].
 * All leaf keypairs are required in order to calculate this value, since each
 * node except for the leaf nodes involves calculating a hash of the 2 child
 * nodes (recursively).
 *
 * See Section 5.3
 *
 * if (r >= 2^h)
 *     T[r] = H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
 * else
 *     T[r] = H(I||u32str(r)||u16str(D_INTR)||T[2r]||T[2r+1]
 *
 * OTS_PUB_HASH[i] is the OTS public key value (K) associated with the
 * OTS private key at position i. (where i = 0...2^h - 1).
 * It is calculated using Algorithm 1.
 *
 * Params:
 *  mdctx: used for the hash function H which has an output size of n bytes.
 *  key: contains lms parameters and keypair info for a LMS tree.
 *  nodeid: tree node id (r) in the range (1...(2^(h+1) - 1))
 *          where the top node is 1, and the leaf nodes start from 2^h.
 *          The leaf nodes are OTS key pairs.
 *  out: the returned public key of size n bytes.

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

    if (ossl_lms_key_node_cache_get(key, nodeid, out))
        return 1;

    //if (nodeid == 1 && key->pub.K != NULL) {
    //    memcpy(out, key->pub.K, n);
    //    return 1;
    //}
    /* H(I||u32str(r) */
    if (!WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)
            || !WPACKET_memcpy(&pkt, key->I, LMS_SIZE_I)
            || !WPACKET_put_bytes_u32(&pkt, nodeid))
        return 0;

    /* Is it a leaf node ? */
    if (nodeid >= leafoffset) {
        uint32_t q = nodeid - leafoffset;
        unsigned char K[LMS_MAX_DIGEST_SIZE];

        ret = ossl_lm_ots_pubK_from_priv(key, q, K)
              && WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_LEAF)
              && WPACKET_get_total_written(&pkt, &len)
              && ossl_lms_hash(key->mdctx, buf, len, K, n, out);
    } else {
        unsigned char tlr[2 * LMS_MAX_DIGEST_SIZE];

        ret = WPACKET_put_bytes_u16(&pkt, OSSL_LMS_D_INTR)
              && WPACKET_get_total_written(&pkt, &len)
              && ossl_lms_key_get_pubkey_from_nodeid(key, 2 * nodeid, tlr)
              && ossl_lms_key_get_pubkey_from_nodeid(key, 2 * nodeid + 1, tlr + n)
              && ossl_lms_hash(key->mdctx, buf, len, tlr, 2 * n, out);
    }
    if (ret)
        ossl_lms_key_node_cache_add(key, nodeid, out);
    return ret;
}

#if 0
/*
 * Algorithm 1 (Step 5)
 *
 * key->pub[] = ots_type || I || q || K
 */
int ossl_lms_key_encode_pub(LMS_KEY *key, uint32_t q, unsigned char *pubK)
{
    if (key->pub == NULL) {
        WPACKET pkt;
        const LM_OTS_PARAMS *prms = key->ots_params;
        uint8_t n = prms->n;

        key->publen = 4 + LMS_ISIZE + 4 + n;
        key->pub = OPENSSL_malloc(key->publen);
        if (key->pub == NULL)
            return 0;
        if (!WPACKET_init_static_len(&pkt, key->pub, key->publen, 0)
                || ! WPACKET_put_bytes_u32(&pkt, prms->lm_ots_type)
                || !WPACKET_memcpy(&pkt, key->I, LMS_ISIZE)
                || !WPACKET_put_bytes_u32(&pkt, q)
                || !WPACKET_memcpy(&pkt, pubK, n)
                || WPACKET_remaining(&pkt) > 0)
            goto err;
        key->pub_allocated = 1;
        key->K = WPACKET_get_curr(pkt) - n;
    }
    return 1;
err:
    OPENSSL_free(key->pub);
    return 0;
}
#endif

static int WPACKET_remaining(WPACKET *pkt)
{
    return pkt->maxsize - pkt->curr;
}

/*
 * Section 5.3 LMS public Key
 *
 * Create an encoded LMS public key which consists of
 * u32str(lmstype) || u32str(otstype) || I || T[1]
 *
 * Where T[1] is calculated by calling ossl_lms_key_get_pubkey_from_nodeid()
 */
int ossl_lms_pub_key_compute(LMS_KEY *lmskey)
{
    int ret = 0;
    LMS_PUB_KEY *pub = &lmskey->pub;
    const LM_OTS_PARAMS *prms = lmskey->ots_params;
    uint8_t n = prms->n;
    WPACKET pkt;

    /* Allocate a buffer for the encoded public key once */
    if (pub->encoded == NULL) {
        pub->encodedlen = LMS_SIZE_PUB_LMS_TYPE + LMS_SIZE_PUB_OTS_TYPE +
                          LMS_SIZE_I + n;
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

        if (!ossl_lms_key_get_pubkey_from_nodeid(lmskey, 1, K))
            goto err;

        if (!WPACKET_put_bytes_u32(&pkt, lmskey->lms_params->lms_type)
                || !WPACKET_put_bytes_u32(&pkt, prms->lm_ots_type)
                || !WPACKET_memcpy(&pkt, lmskey->I, LMS_SIZE_I))
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

/* Generate a LMS key pair */
LMS_KEY *ossl_lms_key_gen(uint32_t lms_type, uint32_t ots_type,
                          OSSL_LIB_CTX *libctx,
                          LMS_KEY *parent)
{
    int ret;
    LMS_KEY *key;

    key = ossl_lms_key_new();
    if (key == NULL)
        return NULL;

    ret = ossl_lms_key_init(key, lms_type, ots_type, libctx)
          && ossl_lms_key_reset(key, 0, parent)
          && ossl_lms_pub_key_compute(key);
    if (ret == 0) {
        ossl_lms_key_free(key);
        key = NULL;
    }
    return key;
}

/*
 * RFC 8554 Algorithm 6: Steps 1 & 2.
 * Steps that involve checking the size of the public key data are
 * done indirectly by checking the return result of PACKET_get API's.
 * This function may be called multiple times when parsing a HSS signature.
 * It is also used by ossl_lms_pub_key_from_data() to load a pubkey.
 */
int ossl_lms_pub_key_from_pkt(PACKET *pkt, LMS_KEY *lmskey)
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
            || !PACKET_get_bytes_shallow(pkt, &lmskey->I, LMS_SIZE_I)
            || !PACKET_get_bytes_shallow(pkt, &key->K, lmskey->lms_params->n))
        goto err;
    key->encodedlen = pkt->curr - key->encoded;
    return 1;
err:
    return 0;
}

size_t ossl_lms_pub_key_encode_len(LMS_KEY *lmskey)
{
    return LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE + LMS_SIZE_I
           + lmskey->lms_params->n;
}

int ossl_lms_pub_key_to_pkt(WPACKET *pkt, LMS_KEY *lmskey)
{
    return WPACKET_put_bytes_u32(pkt, lmskey->lms_params->lms_type)
           && WPACKET_put_bytes_u32(pkt, lmskey->ots_params->lm_ots_type)
           && WPACKET_memcpy(pkt, lmskey->I, LMS_SIZE_I)
           && WPACKET_memcpy(pkt, lmskey->pub.K, lmskey->lms_params->n);
}

#if 0
static int ossl_lms_pub_key_to_pkt(LMS_KEY *lmskey, WPACKET *pkt)
{
    return WPACKET_put_bytes_u32(pkt, lmskey->lms_params->lms_type)
           && WPACKET_put_bytes_u32(pkt, lmskey->ots_params->lm_ots_type)
           && WPACKET_memcpy(pkt, lmskey->I, LMS_SIZE_I)
           && WPACKET_memcpy(pkt, lmskey->pub.K, lmskey->lms_params->n);
}


int ossl_lms_pub_key_encode(LMS_KEY *lmskey, unsigned char *out, size_t *outlen)
{
    WPACKET pkt;

    return WPACKET_init_static_len(&pkt, out, outlen, 0)
           && ossl_lms_pub_key_to_pkt(lmskey, &pkt)
           && WPACKET_remaining(&pkt) == 0;
}
#endif

/*
 * Load a LMS_PUB_KEY from a |pub| byte array of size |publen|.
 * An error is returned if either |pub| is invalid or |publen| is
 * not the correct size (i.e. trailing data is not allowed)
 */
int ossl_lms_pub_key_decode(const unsigned char *pub, size_t publen,
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
            || !ossl_lms_pub_key_from_pkt(&pkt, lmskey)
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
    if (!ossl_lms_key_node_cache_copy(src, dst)
            || !ossl_lms_pub_key_copy(&src->pub, n, &dst->pub)
            || ! ossl_lms_priv_key_copy(&src->priv, n, &dst->priv))
        goto err;
    if (dst->priv.data != NULL)
        dst->I = dst->priv.data;
    else if (dst->pub.K != NULL)
        dst->I = dst->pub.K - n;
    else
        dst->I = NULL;

    return dst;
err:
    ossl_lms_key_free(dst);
    return NULL;
}
