/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h> //temp
#include "crypto/hss.h"
#include "lms_local.h"

#define HSS_MIN_L 1
#define HSS_MAX_L 8

HSS_KEY *ossl_hss_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    HSS_KEY *hsskey = OPENSSL_zalloc(sizeof(*hsskey));

    if (hsskey == NULL)
        return NULL;
    if (!CRYPTO_NEW_REF(&hsskey->references, 1)) {
        OPENSSL_free(hsskey);
        return NULL;
    }
    hsskey->lmskeys = sk_LMS_KEY_new_null();
    hsskey->lmssigs = sk_LMS_SIG_new_null();
    hsskey->libctx = libctx;
    return hsskey;
}

int ossl_hss_key_up_ref(HSS_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("HSS_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

static void ossl_hss_key_reset(HSS_KEY *hsskey)
{
    sk_LMS_SIG_pop_free(hsskey->lmssigs, ossl_lms_sig_free);
    sk_LMS_KEY_pop_free(hsskey->lmskeys, ossl_lms_key_free);
}

void ossl_hss_key_free(HSS_KEY *hsskey)
{
    int i;

    if (hsskey == NULL)
        return;

    CRYPTO_DOWN_REF(&hsskey->references, &i);
    REF_PRINT_COUNT("HSS_KEY", hsskey);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    ossl_hss_key_reset(hsskey);
    CRYPTO_FREE_REF(&hsskey->references);
    OPENSSL_free(hsskey);
}

size_t ossl_hss_pubkey_length(const unsigned char *data, size_t datalen)
{
    PACKET pkt;
    uint32_t L, lms_type;
    const LMS_PARAMS *params;

    if (!PACKET_buf_init(&pkt, data, datalen)
            || !PACKET_get_4_len(&pkt, &L)
            || !PACKET_get_4_len(&pkt, &lms_type)
            || (params = ossl_lms_params_get(lms_type)) == NULL)
        return 0;
    return HSS_SIZE_PUB_L + LMS_SIZE_PUB_LMS_TYPE + LMS_SIZE_PUB_OTS_TYPE
           + LMS_SIZE_I + params->n;
}

int ossl_hss_pub_key_decode(const unsigned char *pub, size_t publen,
                            HSS_KEY *hsskey)
{
    PACKET pkt;
    LMS_KEY *lmskey;

    if (!PACKET_buf_init(&pkt, pub, publen)
            || !PACKET_get_4_len(&pkt, &hsskey->L)
            || hsskey->L < HSS_MIN_L
            || hsskey->L > HSS_MAX_L)
        return 0;


    //ossl_hss_key_reset(hsskey);

    lmskey = ossl_lms_key_new();
    if (lmskey == NULL)
        return 0;
    if (!ossl_lms_pub_key_decode(pkt.curr, pkt.remaining, lmskey)
            || !sk_LMS_KEY_push(hsskey->lmskeys, lmskey)) {
        ossl_lms_key_free(lmskey);
        return 0;
    }
    return 1;
}

int ossl_hss_pub_key_encode(HSS_KEY *hsskey, unsigned char *pub, size_t *publen)
{
    WPACKET pkt;
    LMS_KEY *lmskey;

    if (hsskey == NULL
            || ((lmskey = sk_LMS_KEY_value(hsskey->lmskeys, 0)) == NULL))
        return 0;

    if (pub == NULL) {
        if (publen == NULL)
            return 0;
        *publen = LMS_SIZE_L + ossl_lms_pub_key_encode_len(lmskey);
        return 1;
    }
    return WPACKET_init_static_len(&pkt, pub, *publen, 0)
           && WPACKET_put_bytes_u32(&pkt, hsskey->L)
           && ossl_lms_pub_key_to_pkt(&pkt, lmskey);
}

int ossl_hss_pubkey_from_params(const OSSL_PARAM params[], HSS_KEY *hsskey)
{
    const OSSL_PARAM *p = NULL, *pl = NULL;
    int ok = 0;
    LMS_KEY *lmskey = NULL;

    pl = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_HSS_L);
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (pl != NULL) {
            if (!OSSL_PARAM_get_uint32(pl, &hsskey->L))
                return 0;
            lmskey = ossl_lms_key_new();
            if (lmskey == NULL)
                return 0;
            if (!ossl_lms_pub_key_decode(p->data, p->data_size, lmskey))
                goto err;
        } else {
            if (!ossl_hss_pub_key_decode(p->data, p->data_size, hsskey))
                goto err;
        }
    }

    return 1;
 err:
    ossl_lms_key_free(lmskey);
    return ok;
}

/*
 * Algorithm 7: Generating an HSS Key Pair
 */
int ossl_hss_generate_key(HSS_KEY *hsskey, uint32_t levels,
                          uint32_t *lms_types, uint32_t *ots_types)
{
    uint32_t i;
    LMS_SIG *sig = NULL;
    LMS_KEY *key = NULL;
    LMS_KEY *parent = NULL;

    hsskey->L = levels;

    /* Generate the top level tree key pair */
    hsskey->lmskeys = sk_LMS_KEY_new_null();
    if (hsskey->lmskeys == NULL)
        return 0;
    hsskey->lmssigs = sk_LMS_SIG_new_null();
    if (hsskey->lmssigs == NULL)
        goto err;
    /*
     * Create LMS keypairs and signatures.
     * For each level there is only one LMS tree active.
     */
    for (i = 0; i < levels; ++i) {
        key = ossl_lms_key_gen(lms_types[i], ots_types[i], hsskey->libctx,
                               parent);
        if (key == NULL)
            goto err;
        if (sk_LMS_KEY_push(hsskey->lmskeys, key) <= 0)
            goto err;
        sig = ossl_lms_sig_new();
        if (sig == NULL)
            goto err;
        sig->params = key->lms_params;
        sig->sig.params = key->ots_params;
        if (sk_LMS_SIG_push(hsskey->lmssigs, sig) <= 0)
            goto err;
        sig = NULL;
        parent = key;
    }

    /*
     * For each intermediate tree except the leaf, generate an lms signature,
     * using the private key of the tree above to sign the encoded public key.
     */
    for (i = 1; i < levels; ++i) {
        key = sk_LMS_KEY_value(hsskey->lmskeys, i);
        if (!ossl_lms_signature_gen(sk_LMS_KEY_value(hsskey->lmskeys, i - 1),
                                    key->pub.encoded, key->pub.encodedlen,
                                    sk_LMS_SIG_value(hsskey->lmssigs, i - 1)))
            goto err;
    }
    /* The leaf signature is calculated later when the message is supplied */

    return 1;
err:
    ossl_lms_sig_free(sig);
    sk_LMS_SIG_pop_free(hsskey->lmssigs, ossl_lms_sig_free);
    sk_LMS_KEY_pop_free(hsskey->lmskeys, ossl_lms_key_free);
    return 0;
}

/*
 * Deep copy the existing key and record a count of how many times this
 * new key can be used.
 */
HSS_KEY *ossl_hss_key_reserve(const HSS_KEY *src, uint64_t count)
{
    HSS_KEY *dst;

    if (src->reserved)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    if (!CRYPTO_NEW_REF(&dst->references, 1)) {
        OPENSSL_free(dst);
        return NULL;
    }
    dst->lmskeys = sk_LMS_KEY_deep_copy(src->lmskeys,
                                        ossl_lms_key_deep_copy, ossl_lms_key_free);
    dst->lmssigs = sk_LMS_SIG_deep_copy(src->lmssigs,
                                        ossl_lms_sig_deep_copy, ossl_lms_sig_free);
    if (dst->lmskeys == NULL || dst->lmssigs == NULL)
        goto err;
    dst->L = src->L;
    dst->index = src->index;
    dst->height = src->height;
    dst->libctx = src->libctx;

    dst->reserved = 1;
    dst->remaining = count;
    return dst;
err:
    ossl_hss_key_free(dst);
    return NULL;
}

/*
 * Move forward by 'count' OTS leaf keypairs.
 * Note that all of the non leaf trees have already calculated their signatures
 * so their qindex is off by 1 already..
 */
int ossl_hss_key_advance(HSS_KEY *hsskey, uint64_t count)
{
    LMS_SIG *lmssig;
    uint32_t subtree_leaf_count, remain;
    uint64_t newq[8] = { 0 };
    uint32_t q, d, L = hsskey->L;
    LMS_KEY *lmskey, *parent;

    for (d = L; d > 0; --d) {
        lmskey = sk_LMS_KEY_value(hsskey->lmskeys, d - 1);
        if (lmskey == NULL)
            return 0;
        /*
         * If we move out of the active bottom level sub tree, then we need to
         * figure out how many subtrees are going to be skipped. Then
         * move upwards to the parent subtree, and repeat the same process
         * until we find a parent that is not exhausted. An error should occur
         * if the root would be exhausted.
         */
        subtree_leaf_count = (uint64_t)(1 << lmskey->lms_params->h);

        q = lmskey->q - (d == L ? 0 : 1);
        if (q + count <= subtree_leaf_count) {
            newq[d-1] = q + count;
            break;
        }
        remain = count - (subtree_leaf_count - q);
        count = remain / subtree_leaf_count;    /* This is how far the parent needs to advance */
        newq[d-1] = remain %  subtree_leaf_count; /* The new value for q at this level */
    }
    if (d == 0)
        return 0;

    parent = sk_LMS_KEY_value(hsskey->lmskeys, d - 1);
    for ( ; d < L; ++d) {
        lmskey = sk_LMS_KEY_value(hsskey->lmskeys, d);
        if (!ossl_lms_key_reset(lmskey, parent->q, parent))
            return 0;
        lmskey->q = newq[d - 1];
        if (!ossl_lms_pub_key_compute(lmskey))
            return 0;
        lmssig = sk_LMS_SIG_value(hsskey->lmssigs, d - 1);
        if (!ossl_lms_signature_gen(parent,
                                    lmskey->pub.encoded,
                                    lmskey->pub.encodedlen, lmssig))
            return 0;
        parent = lmskey;
    }
    lmskey = sk_LMS_KEY_value(hsskey->lmskeys, L - 1);
    lmskey->q = newq[L - 1];
    return 1;
}

/* Algorithm 8: Generating a HSS signature */
int ossl_hss_sign(HSS_KEY *hsskey, const unsigned char *msg, size_t msglen,
                  unsigned char *outsig, size_t *outsiglen, size_t outsigmaxlen,
                  OSSL_LIB_CTX *libctx, EVP_MD_CTX *mdctx)
{
    int ret = 0;
    LMS_KEY *lmskey;
    LMS_SIG *lmssig;
    uint32_t i, d, L = hsskey->L;
    WPACKET pkt;
    unsigned char sigbuf[3 * 4 + LMS_MAX_DIGEST_SIZE * (1 + 265 + 25)];
    unsigned char *sigdata = (outsig != NULL) ? sigbuf : NULL;
    size_t len;

    if (hsskey->reserved && hsskey->remaining == 0)
        return 0;

    /*
     * If the Active bottom level tree (depth = L - 1) is exhausted
     * Search upwards until we find a tree level that is not exhausted
     */
    for (d = L; d > 0; --d) {
        lmskey = sk_LMS_KEY_value(hsskey->lmskeys, d - 1);
        if (lmskey == NULL)
            return 0;
        if (lmskey->q < (uint32_t)(1 << lmskey->lms_params->h))
            break;
    }
    /*
     * If the top level tree is exhausted then we can no longer perform
     * signature generation operations since this is a N time OTS scheme.
     * So return an error.
     */
    if (d == 0)
        return 0;
    if (outsig != NULL) {
        LMS_KEY *parent = sk_LMS_KEY_value(hsskey->lmskeys, d - 1);
        for ( ; d < L; ++d) {
           /* Replace any exhausted key pair(s) in the tree */
           lmskey = sk_LMS_KEY_value(hsskey->lmskeys, d);
           if (!ossl_lms_key_reset(lmskey, parent->q, parent))
               return 0;
           if (!ossl_lms_pub_key_compute(lmskey))
               return 0;
           lmssig = sk_LMS_SIG_value(hsskey->lmssigs, d - 1);
           if (!ossl_lms_signature_gen(parent,
                                       lmskey->pub.encoded,
                                       lmskey->pub.encodedlen, lmssig))
               goto err;
           parent = lmskey;
        }
        lmskey = sk_LMS_KEY_value(hsskey->lmskeys, L - 1);
        lmssig = sk_LMS_SIG_value(hsskey->lmssigs, L - 1);
        if (!ossl_lms_signature_gen(lmskey, msg, msglen, lmssig))
            goto err;
        if (!WPACKET_init_static_len(&pkt, outsig, outsigmaxlen, 0))
            goto err;
    } else {
        if (!WPACKET_init_null(&pkt, outsigmaxlen))
            goto err;
    }

    if (!WPACKET_put_bytes_u32(&pkt, L - 1))
        goto err;
    for (i = 0; i < L - 1; ++i) {
        /* Write out signed public keys */
        lmssig = sk_LMS_SIG_value(hsskey->lmssigs, i);
        lmskey = sk_LMS_KEY_value(hsskey->lmskeys, i + 1);
        len = sizeof(sigbuf);
        if (!ossl_lms_sig_encode(lmssig, sigdata, &len)
                || !WPACKET_memcpy(&pkt, sigdata, len)
                || !WPACKET_memcpy(&pkt, lmskey->pub.encoded,
                                   lmskey->pub.encodedlen))
            goto err;
    }
    /* Write out the signed message */
    len = sizeof(sigbuf);
    lmssig = sk_LMS_SIG_value(hsskey->lmssigs, L - 1);
    if (!ossl_lms_sig_encode(lmssig, sigdata, &len)
            || !WPACKET_memcpy(&pkt, sigdata, len)
            || !WPACKET_get_total_written(&pkt, &len))
        goto err;
    *outsiglen = len;
#if 0
    if (outsig != NULL) {
        // TEMP
        {
            unsigned char tmp[32];
            int nodes[] = { 1, 2, 3, 4, 5, 8, 9,16,17, 32, 33, -1};
            int j;
            char *hxbuf;
            fprintf(stdout, "\n\nNODES\n");
            lmskey = sk_LMS_KEY_value(hsskey->lmskeys, 0);
            for (j = 0; nodes[j] > 0; ++j) {
                ossl_lms_key_get_pubkey_from_nodeid(lmskey, nodes[j], tmp);
                hxbuf = OPENSSL_buf2hexstr(tmp, 32);
                fprintf(stdout, "  %02d:  %s\n", nodes[j],  hxbuf);
            }
        }
#ifndef FIPS_MODULE
        {
            BIO *bio = BIO_new_fp(stdout, 0);
            BIO_printf(bio, "\n\nHSS Signature\n");
            ossl_hss_sig_to_text(bio, hsskey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
        }
#endif
    }
#endif

    ret = 1;
    if (hsskey->reserved)
        hsskey->remaining -= 1;
err:
    WPACKET_finish(&pkt);
    return ret;
}
