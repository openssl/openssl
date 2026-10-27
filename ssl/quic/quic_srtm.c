/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_srtm.h"
#include "internal/common.h"
#include "internal/htable.h"
#include <openssl/core_names.h>
#include <openssl/rand.h>

/*
 * QUIC Stateless Reset Token Manager
 * ==================================
 */
typedef struct srtm_item_st SRTM_ITEM;

#define BLINDED_SRT_LEN 16

/*
 * The SRTM is implemented using two hash tables, one matching opaque pointers
 * to an item structure, and another matching a SRT-derived value to an item
 * structure. Multiple items with different seq_num values under a given opaque,
 * and duplicate SRTs, are handled using sorted singly-linked lists: only the
 * head of each list is in the table, through a node embedded in the item.
 *
 * The O(n) insert and lookup performance is tolerated on the basis that the
 * total number of entries for a given opaque (total number of extant CIDs for a
 * connection) should be quite small, and the QUIC protocol allows us to place a
 * hard limit on this via the active_connection_id_limit TPARAM. Thus there is
 * no risk of a large number of SRTs needing to be registered under a given
 * opaque.
 *
 * It is expected one SRTM will exist per QUIC_PORT and track all SRTs across
 * all connections for that QUIC_PORT. Each table has a fixed number of
 * buckets (32 KB on LP64), so chains stay short up to a few thousand
 * connections per port and only lengthen beyond that.
 */
struct srtm_item_st {
    SRTM_ITEM *next_by_srt_blinded; /* SORT BY opaque  DESC */
    SRTM_ITEM *next_by_seq_num; /* SORT BY seq_num DESC */
    void *opaque; /* \__ unique identity for item */
    uint64_t seq_num; /* /                            */
    QUIC_STATELESS_RESET_TOKEN srt;
    unsigned char srt_blinded[BLINDED_SRT_LEN]; /* H(srt) */

    OSSL_QUEUE_MEMBER(fwd); /* in items_fwd while head of its opaque list */
    OSSL_QUEUE_MEMBER(rev); /* in items_rev while head of its SRT list */

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    uint32_t debug_token;
#endif
};

#define SRTM_BITS 12

DEFINE_QUEUE_OF(fwd, SRTM_ITEM);
DEFINE_HTABLE_OF(fwd, SRTM_ITEM, SRTM_BITS);
DEFINE_QUEUE_OF(rev, SRTM_ITEM);
DEFINE_HTABLE_OF(rev, SRTM_ITEM, SRTM_BITS);

struct quic_srtm_st {
    /* Crypto context used to calculate blinded SRTs H(srt). */
    EVP_CIPHER_CTX *blind_ctx; /* kept with key */

    OSSL_HTABLE(fwd)
    items_fwd; /* (opaque)  -> SRTM_ITEM */
    OSSL_HTABLE(rev)
    items_rev; /* (H(srt))  -> SRTM_ITEM */
};

static uint64_t items_rev_hash(const unsigned char *srt_blinded)
{
    /*
     * srt_blinded has already been through a crypto-grade hash function, so we
     * can just use bits from that.
     */
    uint64_t l;

    memcpy(&l, srt_blinded, sizeof(l));
    return l;
}

/* The head of the seq_num-sorted list of items under |opaque|, or NULL. */
static SRTM_ITEM *srtm_fwd_head(const QUIC_SRTM *srtm, void *opaque)
{
    SRTM_ITEM *item;

    OSSL_HTABLE_FIND(item, fwd, &srtm->items_fwd, ossl_hash_ptr(opaque),
        item->opaque == opaque);
    return item;
}

/* The head of the opaque-sorted list of items with |srt_blinded|, or NULL. */
static SRTM_ITEM *srtm_rev_head(const QUIC_SRTM *srtm,
    const unsigned char *srt_blinded)
{
    SRTM_ITEM *item;

    /*
     * We don't need to use CRYPTO_memcmp here as the relationship of
     * srt_blinded to srt is already cryptographically obfuscated.
     */
    OSSL_HTABLE_FIND(item, rev, &srtm->items_rev, items_rev_hash(srt_blinded),
        memcmp(item->srt_blinded, srt_blinded, BLINDED_SRT_LEN) == 0);
    return item;
}

/*
 * Make |new_head| (NULL for none) the item in the forward table in place of
 * |old_head| (NULL for none).
 */
static void srtm_fwd_set_head(QUIC_SRTM *srtm, SRTM_ITEM *old_head,
    SRTM_ITEM *new_head)
{
    if (old_head == new_head)
        return;
    if (old_head != NULL)
        ossl_htable_fwd_del(&srtm->items_fwd, old_head);
    if (new_head != NULL)
        ossl_htable_fwd_add(&srtm->items_fwd, new_head,
            ossl_hash_ptr(new_head->opaque));
}

/* As above, for the reverse table. */
static void srtm_rev_set_head(QUIC_SRTM *srtm, SRTM_ITEM *old_head,
    SRTM_ITEM *new_head)
{
    if (old_head == new_head)
        return;
    if (old_head != NULL)
        ossl_htable_rev_del(&srtm->items_rev, old_head);
    if (new_head != NULL)
        ossl_htable_rev_add(&srtm->items_rev, new_head,
            items_rev_hash(new_head->srt_blinded));
}

QUIC_SRTM *ossl_quic_srtm_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    QUIC_SRTM *srtm = NULL;
    unsigned char key[16];
    EVP_CIPHER *ecb = NULL;

    if (RAND_priv_bytes_ex(libctx, key, sizeof(key), sizeof(key) * 8) != 1)
        goto err;

    if ((srtm = OPENSSL_zalloc(sizeof(*srtm))) == NULL)
        return NULL;

    /* Use AES-128-ECB as a permutation over 128-bit SRTs. */
    if ((ecb = EVP_CIPHER_fetch(libctx, "AES-128-ECB", propq)) == NULL)
        goto err;

    if ((srtm->blind_ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    if (!EVP_EncryptInit_ex2(srtm->blind_ctx, ecb, key, NULL, NULL))
        goto err;

    EVP_CIPHER_free(ecb);
    ecb = NULL;

    ossl_htable_fwd_init(&srtm->items_fwd);
    ossl_htable_rev_init(&srtm->items_rev);
    return srtm;

err:
    /*
     * No cleansing of key needed as blinding exists only for side channel
     * mitigation.
     */
    ossl_quic_srtm_free(srtm);
    EVP_CIPHER_free(ecb);
    return NULL;
}

/* Free a whole opaque list; the reverse table is dropped without a visit. */
static void srtm_free_each(SRTM_ITEM *ihead, void *arg)
{
    SRTM_ITEM *inext, *item = ihead;

    for (item = item->next_by_seq_num; item != NULL; item = inext) {
        inext = item->next_by_seq_num;
        OPENSSL_free(item);
    }

    OPENSSL_free(ihead);
}

void ossl_quic_srtm_free(QUIC_SRTM *srtm)
{
    if (srtm == NULL)
        return;

    ossl_htable_fwd_doall_arg(&srtm->items_fwd, srtm_free_each, NULL);
    EVP_CIPHER_CTX_free(srtm->blind_ctx);
    OPENSSL_free(srtm);
}

/*
 * Find a SRTM_ITEM by (opaque, seq_num). Returns NULL if no match.
 * If head is non-NULL, writes the head of the relevant opaque list to *head if
 * there is one.
 * If prev is non-NULL, writes the previous node to *prev or NULL if it is
 * the first item.
 */
static SRTM_ITEM *srtm_find(QUIC_SRTM *srtm, void *opaque, uint64_t seq_num,
    SRTM_ITEM **head_p, SRTM_ITEM **prev_p)
{
    SRTM_ITEM *item, *prev = NULL;

    item = srtm_fwd_head(srtm, opaque);
    if (head_p != NULL)
        *head_p = item;

    for (; item != NULL; prev = item, item = item->next_by_seq_num)
        if (item->seq_num == seq_num) {
            break;
        } else if (item->seq_num < seq_num) {
            /*
             * List is sorted in descending order so there can't be any match
             * after this.
             */
            item = NULL;
            break;
        }

    if (prev_p != NULL)
        *prev_p = prev;

    return item;
}

/*
 * Inserts a SRTM_ITEM into the singly-linked by-sequence-number linked list.
 * The new head pointer is written to *new_head (which may or may not be
 * unchanged).
 */
static void sorted_insert_seq_num(SRTM_ITEM *head, SRTM_ITEM *item, SRTM_ITEM **new_head)
{
    uint64_t seq_num = item->seq_num;
    SRTM_ITEM *cur = head, **fixup = new_head;

    *new_head = head;

    while (cur != NULL && cur->seq_num > seq_num) {
        fixup = &cur->next_by_seq_num;
        cur = cur->next_by_seq_num;
    }

    item->next_by_seq_num = *fixup;
    *fixup = item;
}

/*
 * Inserts a SRTM_ITEM into the singly-linked by-SRT list.
 * The new head pointer is written to *new_head (which may or may not be
 * unchanged).
 */
static void sorted_insert_srt(SRTM_ITEM *head, SRTM_ITEM *item, SRTM_ITEM **new_head)
{
    uintptr_t opaque = (uintptr_t)item->opaque;
    SRTM_ITEM *cur = head, **fixup = new_head;

    *new_head = head;

    while (cur != NULL && (uintptr_t)cur->opaque > opaque) {
        fixup = &cur->next_by_srt_blinded;
        cur = cur->next_by_srt_blinded;
    }

    item->next_by_srt_blinded = *fixup;
    *fixup = item;
}

/*
 * Computes the blinded SRT value used for internal lookup for side channel
 * mitigation purposes. We compute this once as a cached value when an SRTM_ITEM
 * is formed.
 */
static int srtm_compute_blinded(QUIC_SRTM *srtm, unsigned char *srt_blinded,
    const QUIC_STATELESS_RESET_TOKEN *token)
{
    int outl = 0;

    /*
     * We use AES-128-ECB as a permutation using a random key to facilitate
     * blinding for side-channel purposes. Encrypt the token as a single AES
     * block.
     */
    if (!EVP_EncryptUpdate(srtm->blind_ctx, srt_blinded, &outl,
            (const unsigned char *)token, sizeof(*token)))
        return 0;

    if (!ossl_assert(outl == sizeof(*token)))
        return 0;

    return 1;
}

int ossl_quic_srtm_add(QUIC_SRTM *srtm, void *opaque, uint64_t seq_num,
    const QUIC_STATELESS_RESET_TOKEN *token)
{
    SRTM_ITEM *item = NULL, *head = NULL, *new_head, *r_head;

    /* (opaque, seq_num) duplicates not allowed */
    if ((item = srtm_find(srtm, opaque, seq_num, &head, NULL)) != NULL)
        return 0;

    if ((item = OPENSSL_zalloc(sizeof(*item))) == NULL)
        return 0;

    item->opaque = opaque;
    item->seq_num = seq_num;
    item->srt = *token;
    if (!srtm_compute_blinded(srtm, item->srt_blinded, &item->srt)) {
        OPENSSL_free(item);
        return 0;
    }

    /* Add to forward mapping. */
    sorted_insert_seq_num(head, item, &new_head);
    srtm_fwd_set_head(srtm, head, new_head);

    /* Add to reverse mapping. */
    r_head = srtm_rev_head(srtm, item->srt_blinded);
    sorted_insert_srt(r_head, item, &new_head);
    srtm_rev_set_head(srtm, r_head, new_head);
    return 1;
}

/* Remove item from reverse mapping. */
static void srtm_remove_from_rev(QUIC_SRTM *srtm, SRTM_ITEM *item)
{
    SRTM_ITEM *rh_item;

    rh_item = srtm_rev_head(srtm, item->srt_blinded);
    assert(rh_item != NULL);
    if (rh_item == item) {
        /* The item after this one heads the list now, if there is one. */
        srtm_rev_set_head(srtm, item, item->next_by_srt_blinded);
    } else {
        /* Find our entry in the SRT list */
        for (; rh_item->next_by_srt_blinded != item;
            rh_item = rh_item->next_by_srt_blinded)
            ;
        rh_item->next_by_srt_blinded = item->next_by_srt_blinded;
    }
}

int ossl_quic_srtm_remove(QUIC_SRTM *srtm, void *opaque, uint64_t seq_num,
    uint8_t *match)
{
    SRTM_ITEM *item, *prev = NULL;
    uint8_t match_sink;

    if (match == NULL)
        match = &match_sink;
    *match = 0;

    if ((item = srtm_find(srtm, opaque, seq_num, NULL, &prev)) == NULL)
        /* No match */
        return 1;

    *match = 1;

    /* Remove from forward mapping. */
    if (prev == NULL)
        srtm_fwd_set_head(srtm, item, item->next_by_seq_num);
    else
        prev->next_by_seq_num = item->next_by_seq_num;

    /* Remove from reverse mapping. */
    srtm_remove_from_rev(srtm, item);

    OPENSSL_free(item);
    return 1;
}

int ossl_quic_srtm_cull(QUIC_SRTM *srtm, void *opaque)
{
    SRTM_ITEM *item, *inext, *ihead;

    if ((ihead = srtm_fwd_head(srtm, opaque)) == NULL)
        return 1; /* nothing removed is a success condition */

    srtm_fwd_set_head(srtm, ihead, NULL);
    for (item = ihead; item != NULL; item = inext) {
        inext = item->next_by_seq_num;
        srtm_remove_from_rev(srtm, item);
        OPENSSL_free(item);
    }

    return 1;
}

int ossl_quic_srtm_lookup(QUIC_SRTM *srtm,
    const QUIC_STATELESS_RESET_TOKEN *token,
    size_t idx,
    void **opaque, uint64_t *seq_num)
{
    unsigned char srt_blinded[BLINDED_SRT_LEN];
    SRTM_ITEM *item;

    if (!srtm_compute_blinded(srtm, srt_blinded, token))
        return 0;

    item = srtm_rev_head(srtm, srt_blinded);
    for (; idx > 0 && item != NULL; --idx, item = item->next_by_srt_blinded)
        ;
    if (item == NULL)
        return 0;

    if (opaque != NULL)
        *opaque = item->opaque;
    if (seq_num != NULL)
        *seq_num = item->seq_num;

    return 1;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

static uint32_t token_next = 0x5eadbeef;
static size_t tokens_seen;

struct check_args {
    uint32_t token;
    int mode;
};

static void check_mark(SRTM_ITEM *item, void *arg)
{
    struct check_args *arg_ = arg;
    uint32_t token = arg_->token;
    ossl_unused uint64_t prev_seq_num = 0;
    ossl_unused void *prev_opaque = NULL;
    int have_prev = 0;

    assert(item != NULL);

    while (item != NULL) {
        if (have_prev) {
            assert(!(item->opaque == prev_opaque && item->seq_num == prev_seq_num));
            if (!arg_->mode)
                assert(item->opaque != prev_opaque || item->seq_num < prev_seq_num);
        }

        ++tokens_seen;
        item->debug_token = token;
        prev_opaque = item->opaque;
        prev_seq_num = item->seq_num;
        have_prev = 1;

        if (arg_->mode)
            item = item->next_by_srt_blinded;
        else
            item = item->next_by_seq_num;
    }
}

static void check_count(SRTM_ITEM *item, void *arg)
{
    struct check_args *arg_ = arg;
    ossl_unused uint32_t token = arg_->token;

    assert(item != NULL);

    while (item != NULL) {
        ++tokens_seen;
        assert(item->debug_token == token);

        if (arg_->mode)
            item = item->next_by_seq_num;
        else
            item = item->next_by_srt_blinded;
    }
}

/* Visit the head of every opaque list (fwd) or SRT list (rev). */
static void check_each_fwd(const QUIC_SRTM *srtm,
    void (*fn)(SRTM_ITEM *, void *), void *arg)
{
    SRTM_ITEM *item;
    size_t i;

    for (i = 0; i < ossl_htable_num_buckets(&srtm->items_fwd); i++)
        OSSL_QUEUE_FOREACH (item, fwd, &srtm->items_fwd.buckets[i])
            fn(item, arg);
}

static void check_each_rev(const QUIC_SRTM *srtm,
    void (*fn)(SRTM_ITEM *, void *), void *arg)
{
    SRTM_ITEM *item;
    size_t i;

    for (i = 0; i < ossl_htable_num_buckets(&srtm->items_rev); i++)
        OSSL_QUEUE_FOREACH (item, rev, &srtm->items_rev.buckets[i])
            fn(item, arg);
}

#endif

void ossl_quic_srtm_check(const QUIC_SRTM *srtm)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    struct check_args args = { 0 };
    size_t tokens_expected;
    ossl_unused size_t tokens_expected_old;

    args.token = token_next;
    ++token_next;

    assert(srtm != NULL);
    assert(srtm->blind_ctx != NULL);

    tokens_seen = 0;
    check_each_fwd(srtm, check_mark, &args);

    tokens_expected = tokens_seen;
    tokens_seen = 0;
    check_each_rev(srtm, check_count, &args);

    assert(tokens_seen == tokens_expected);
    tokens_expected_old = tokens_expected;

    args.token = token_next;
    ++token_next;

    args.mode = 1;
    tokens_seen = 0;
    check_each_rev(srtm, check_mark, &args);

    tokens_expected = tokens_seen;
    tokens_seen = 0;
    check_each_fwd(srtm, check_count, &args);

    assert(tokens_seen == tokens_expected);
    assert(tokens_seen == tokens_expected_old);
#endif
}
