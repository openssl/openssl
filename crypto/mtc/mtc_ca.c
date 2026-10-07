/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * The identity core of a trusted Merkle Tree Certification Authority, built
 * from configured fields (section 7.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 * See include/crypto/mtc_ca.h.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>

#include "crypto/mtc.h"
#include "crypto/ctype.h"
#include "crypto/mtc_ca.h"

static void subtree_free(OSSL_MTC_TRUSTED_SUBTREE *ts);
static void log_free(OSSL_MTC_LOG *log);
static void advertised_ids_repack(OSSL_MTC_CA *ca);

/*
 * The room one issuance log needs in the CA's advertisement buffer: its
 * u8-length-prefixed landmark group ID, the CA ID with three relative-OID
 * components of at most ten bytes each appended (section 8.2.1).  Also fits the
 * bare CA ID.
 */
#define MTC_ADVERTISED_ID_SLOT (1 + OSSL_MTC_CA_ID_MAX + 3 * 10)

OSSL_MTC_CA *ossl_mtc_ca_new(const uint8_t *ca_id, size_t ca_id_len,
    const EVP_MD *hash, uint64_t min_serial, EVP_PKEY *cosigner_pkey)
{
    OSSL_MTC_CA *ca;

    /* Advertised IDs derived from the CA ID must fit their u8 length prefix. */
    if (ca_id_len == 0 || ca_id_len > OSSL_MTC_CA_ID_MAX)
        return NULL;

    if ((ca = OPENSSL_zalloc(sizeof(*ca))) == NULL)
        return NULL;

    ca->lock = CRYPTO_THREAD_lock_new();
    ca->ca_id = OPENSSL_memdup(ca_id, ca_id_len);
    ca->advertised_ids = OPENSSL_malloc(MTC_ADVERTISED_ID_SLOT);
    /*
     * The references on hash and cosigner_pkey are taken last, so that until
     * they are recorded below there is nothing for ossl_mtc_ca_free() to
     * release.
     */
    if (ca->lock == NULL || ca->ca_id == NULL || ca->advertised_ids == NULL
        || !EVP_MD_up_ref((EVP_MD *)hash)) {
        ossl_mtc_ca_free(ca);
        return NULL;
    }
    ca->hash = (EVP_MD *)hash;
    if (!EVP_PKEY_up_ref(cosigner_pkey)) {
        ossl_mtc_ca_free(ca);
        return NULL;
    }

    ca->ca_id_len = ca_id_len;
    ca->min_serial = min_serial;
    ca->max_serial = UINT64_MAX;
    ca->cosigner_pkey = cosigner_pkey;
    /* With no landmark state yet, the CA advertises its bare CA ID. */
    advertised_ids_repack(ca);
    return ca;
}

void ossl_mtc_ca_free(OSSL_MTC_CA *ca)
{
    if (ca == NULL)
        return;
    OPENSSL_free(ca->revoked);
    sk_OSSL_MTC_LOG_pop_free(ca->logs, log_free);
    OPENSSL_free(ca->advertised_ids);
    OPENSSL_free(ca->ca_id);
    EVP_MD_free(ca->hash);
    EVP_PKEY_free(ca->cosigner_pkey);
    CRYPTO_THREAD_lock_free(ca->lock);
    OPENSSL_free(ca);
}

int ossl_mtc_ca_add_revoked_range(OSSL_MTC_CA *ca, uint64_t start, uint64_t end)
{
    OSSL_MTC_SERIAL_RANGE *tmp;
    int ret = 0;

    if (start >= end) /* the half-open range must be non-empty */
        return 0;

    if (!CRYPTO_THREAD_write_lock(ca->lock))
        return 0;

    tmp = OPENSSL_realloc_array(ca->revoked, ca->revoked_count + 1,
        sizeof(*ca->revoked));
    if (tmp == NULL)
        goto out;
    ca->revoked = tmp;

    ca->revoked[ca->revoked_count].start = start;
    ca->revoked[ca->revoked_count].end = end;
    ca->revoked_count++;
    ret = 1;
out:
    CRYPTO_THREAD_unlock(ca->lock);
    return ret;
}

int ossl_mtc_ca_serial_is_revoked(const OSSL_MTC_CA *ca, uint64_t serial)
{
    size_t i;
    int revoked = 0;

    /* If the lock cannot be taken, fail closed by reporting revoked. */
    if (!CRYPTO_THREAD_read_lock(ca->lock))
        return 1;

    /* Implied revoked ranges [0, min_serial) and (max_serial, 2^64). */
    if (serial < ca->min_serial || serial > ca->max_serial) {
        revoked = 1;
    } else {
        for (i = 0; i < ca->revoked_count; i++) {
            if (serial >= ca->revoked[i].start && serial < ca->revoked[i].end) {
                revoked = 1;
                break;
            }
        }
    }

    CRYPTO_THREAD_unlock(ca->lock);
    return revoked;
}

const uint8_t *ossl_mtc_ca_id(const OSSL_MTC_CA *ca, size_t *len)
{
    *len = ca->ca_id_len;
    return ca->ca_id;
}

const EVP_MD *ossl_mtc_ca_hash(const OSSL_MTC_CA *ca)
{
    return ca->hash;
}

EVP_PKEY *ossl_mtc_ca_cosigner_pkey(const OSSL_MTC_CA *ca)
{
    return ca->cosigner_pkey;
}

/* Order subtrees within a log ascending by (start, end). */
static int subtree_cmp(const OSSL_MTC_TRUSTED_SUBTREE *const *a,
    const OSSL_MTC_TRUSTED_SUBTREE *const *b)
{
    if ((*a)->start != (*b)->start)
        return (*a)->start < (*b)->start ? -1 : 1;
    if ((*a)->end != (*b)->end)
        return (*a)->end < (*b)->end ? -1 : 1;
    return 0;
}

static void subtree_free(OSSL_MTC_TRUSTED_SUBTREE *ts)
{
    if (ts == NULL)
        return;
    OPENSSL_free(ts->hash);
    OPENSSL_free(ts);
}

/* Order issuance logs ascending by log number. */
static int log_cmp(const OSSL_MTC_LOG *const *a, const OSSL_MTC_LOG *const *b)
{
    if ((*a)->log_number != (*b)->log_number)
        return (*a)->log_number < (*b)->log_number ? -1 : 1;
    return 0;
}

static void log_free(OSSL_MTC_LOG *log)
{
    if (log == NULL)
        return;
    sk_OSSL_MTC_TRUSTED_SUBTREE_pop_free(log->subtrees, subtree_free);
    OPENSSL_free(log);
}

/* Find a CA's issuance log by number, or NULL if it has none. */
static OSSL_MTC_LOG *find_log(const OSSL_MTC_CA *ca, uint64_t log_number)
{
    OSSL_MTC_LOG key;
    int idx;

    if (ca->logs == NULL)
        return NULL;
    key.log_number = log_number;
    idx = sk_OSSL_MTC_LOG_find(ca->logs, &key);
    return idx < 0 ? NULL : sk_OSSL_MTC_LOG_value(ca->logs, idx);
}

/* Find a CA's issuance log by number, creating and inserting it if absent. */
static OSSL_MTC_LOG *find_or_create_log(OSSL_MTC_CA *ca, uint64_t log_number)
{
    OSSL_MTC_LOG *log = find_log(ca, log_number);
    uint8_t *tmp;

    if (log != NULL)
        return log;

    if (ca->logs == NULL
        && (ca->logs = sk_OSSL_MTC_LOG_new(log_cmp)) == NULL)
        return NULL;

    /*
     * Grow the CA's advertisement buffer to cover the new log, so that
     * repacking it after any later update cannot fail.  Growing here
     * piggybacks on the allocation that adding a log already is; a failure
     * leaves the CA unchanged (and a larger buffer is harmless if a later
     * step fails).
     */
    tmp = OPENSSL_realloc(ca->advertised_ids,
        (size_t)(sk_OSSL_MTC_LOG_num(ca->logs) + 1) * MTC_ADVERTISED_ID_SLOT);
    if (tmp == NULL)
        return NULL;
    ca->advertised_ids = tmp;

    if ((log = OPENSSL_zalloc(sizeof(*log))) == NULL)
        return NULL;
    log->log_number = log_number;
    if ((log->subtrees = sk_OSSL_MTC_TRUSTED_SUBTREE_new(subtree_cmp)) == NULL
        || !sk_OSSL_MTC_LOG_push(ca->logs, log)) {
        log_free(log);
        return NULL;
    }
    (void)sk_OSSL_MTC_LOG_sort(ca->logs); /* keep sorted for lock-free reads */
    return log;
}

/* Find a subtree in a sorted stack by (start, end), or NULL if absent. */
static OSSL_MTC_TRUSTED_SUBTREE *subtrees_find(
    STACK_OF(OSSL_MTC_TRUSTED_SUBTREE) *subtrees, uint64_t start, uint64_t end)
{
    OSSL_MTC_TRUSTED_SUBTREE key;
    int idx;

    if (subtrees == NULL)
        return NULL;
    key.start = start;
    key.end = end;
    idx = sk_OSSL_MTC_TRUSTED_SUBTREE_find(subtrees, &key);
    return idx < 0 ? NULL : sk_OSSL_MTC_TRUSTED_SUBTREE_value(subtrees, idx);
}

/*
 * Insert ts into subtrees, keeping it sorted by (start, end).  On a duplicate
 * (start, end), sets *dup and returns 0 without inserting; ts is not consumed.
 * On success ts is owned by the stack.
 */
static int subtrees_insert(STACK_OF(OSSL_MTC_TRUSTED_SUBTREE) *subtrees,
    OSSL_MTC_TRUSTED_SUBTREE *ts, int *dup)
{
    *dup = 0;
    if (subtrees_find(subtrees, ts->start, ts->end) != NULL) {
        *dup = 1;
        return 0;
    }
    if (!sk_OSSL_MTC_TRUSTED_SUBTREE_push(subtrees, ts))
        return 0;
    (void)sk_OSSL_MTC_TRUSTED_SUBTREE_sort(subtrees);
    return 1;
}

int ossl_mtc_ca_set_max_serial(OSSL_MTC_CA *ca, uint64_t max_serial)
{
    if (!CRYPTO_THREAD_write_lock(ca->lock))
        return 0;
    ca->max_serial = max_serial;
    CRYPTO_THREAD_unlock(ca->lock);
    return 1;
}

/* Tree sizes and landmark numbers are below 2^48 (section 6.4.3). */
#define MTC_MAX_TREE_SIZE (UINT64_C(1) << 48)

/*
 * Parse the decimal representation of a non-negative integer (section 2),
 * with nothing before or after it.
 */
static int parse_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;

    if (!ossl_isdigit(*s))
        return 0;
    if (s[0] == '0' && s[1] != '\0')
        return 0;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || *end != '\0')
        return 0;
    *out = (uint64_t)v;
    return 1;
}

/*
 * Read one newline-terminated line of in into buf, without the newline.
 * Fails on a missing newline or a line longer than the buffer.
 */
static int read_line(BIO *in, char *buf, int buf_len)
{
    int len;

    if ((len = BIO_gets(in, buf, buf_len)) <= 0 || buf[len - 1] != '\n')
        return 0;
    buf[len - 1] = '\0';
    return 1;
}

/**
 * @brief Read the landmark description of section 6.4.3.
 *
 * The description is a line holding latest_landmark, then lines
 * "<tree size> <expiry>" for landmarks latest_landmark, latest_landmark - 1,
 * and so on, with tree sizes strictly decreasing and below MTC_MAX_TREE_SIZE
 * and expiries non-increasing.  The first line whose expiry is before cutoff,
 * or else the last line, ends the description: it only bounds the landmark
 * above it.  Lines after it are not read.
 *
 * @param in the description to read
 * @param cutoff the POSIX time before which landmarks are not loaded
 * @param out_last_landmark set to latest_landmark
 * @param out_sizes set to the tree sizes read, newest first (caller frees)
 * @param out_size_count set to the number of tree sizes read
 * @returns 1 on success, 0 on malformed input or allocation failure.
 */
static int read_landmarks(BIO *in, int64_t cutoff,
    uint64_t *out_last_landmark, uint64_t **out_sizes, size_t *out_size_count)
{
    char line[64], *space;
    uint64_t last_landmark, size, expiry, prev_expiry = 0;
    uint64_t *sizes = NULL, *tmp;
    size_t count = 0, cap = 0;
    int len, ret = 0;

    if (!read_line(in, line, sizeof(line))
        || !parse_u64(line, &last_landmark)
        || last_landmark >= MTC_MAX_TREE_SIZE)
        goto err;

    for (;;) {
        if ((len = BIO_gets(in, line, sizeof(line))) <= 0) {
            if (count == 0)
                goto err;
            break;
        }
        if (line[len - 1] != '\n')
            goto err;
        line[len - 1] = '\0';
        if ((space = strchr(line, ' ')) == NULL)
            goto err;
        *space = '\0';
        if (!parse_u64(line, &size) || !parse_u64(space + 1, &expiry))
            goto err;

        /* This line is landmark last_landmark - count. */
        if (count > last_landmark)
            goto err;
        if (size >= MTC_MAX_TREE_SIZE || expiry > INT64_MAX)
            goto err;
        if (count > 0 && (size >= sizes[count - 1] || expiry > prev_expiry))
            goto err;

        if (count == cap) {
            size_t new_cap = cap == 0 ? 8 : cap * 2;

            if ((tmp = OPENSSL_realloc_array(sizes, new_cap, sizeof(*sizes)))
                == NULL)
                goto err;
            sizes = tmp;
            cap = new_cap;
        }
        sizes[count++] = size;
        prev_expiry = expiry;

        if ((int64_t)expiry < cutoff)
            break;
    }

    *out_last_landmark = last_landmark;
    *out_sizes = sizes;
    *out_size_count = count;
    sizes = NULL;
    ret = 1;
err:
    OPENSSL_free(sizes);
    return ret;
}

int ossl_mtc_ca_load_landmarks(OSSL_MTC_CA *ca, uint64_t log_number, BIO *in,
    int64_t cutoff)
{
    uint64_t last_landmark, *sizes = NULL;
    size_t size_count, i;
    STACK_OF(OSSL_MTC_TRUSTED_SUBTREE) *new_subtrees = NULL, *old_subtrees;
    OSSL_MTC_LOG *log;
    int locked = 0, ret = 0;

    if (!read_landmarks(in, cutoff, &last_landmark, &sizes, &size_count))
        goto err;

    /*
     * Build the replacement window off to the side, so a failure leaves the CA
     * untouched.  Each loaded landmark j (= last_landmark - i, for i in
     * [0, size_count - 1)) covers [tree_size(j-1), tree_size(j)) =
     * [sizes[i+1], sizes[i]); its covering subtrees are its landmark subtrees
     * (6.4.1).
     */
    if ((new_subtrees = sk_OSSL_MTC_TRUSTED_SUBTREE_new(subtree_cmp)) == NULL)
        goto err;

    if (!CRYPTO_THREAD_write_lock(ca->lock))
        goto err;
    locked = 1;

    log = find_log(ca, log_number); /* existing window, for carrying hashes */
    old_subtrees = log == NULL ? NULL : log->subtrees;

    for (i = 0; i + 1 < size_count; i++) {
        OSSL_MTC_SUBTREE interval, cover[2];
        uint64_t landmark = last_landmark - i;
        size_t k;

        interval.start = sizes[i + 1];
        interval.end = sizes[i]; /* strictly decreasing => start < end */
        ossl_mtc_find_subtrees(interval, cover);
        for (k = 0; k < 2; k++) {
            OSSL_MTC_TRUSTED_SUBTREE *ts, *prev;
            int dup = 0;

            /* An empty covering subtree is never trusted. */
            if (cover[k].start == cover[k].end)
                continue;
            /* A subtree already contributed by a newer landmark is the same. */
            if (subtrees_find(new_subtrees, cover[k].start, cover[k].end)
                != NULL)
                continue;
            if ((ts = OPENSSL_zalloc(sizeof(*ts))) == NULL)
                goto err;
            ts->landmark = landmark;
            ts->start = cover[k].start;
            ts->end = cover[k].end;
            /* Carry over a hash already vetted for this exact subtree. */
            prev = subtrees_find(old_subtrees, cover[k].start, cover[k].end);
            if (prev != NULL && prev->hash != NULL) {
                if ((ts->hash = OPENSSL_memdup(prev->hash, prev->hash_len))
                    == NULL) {
                    subtree_free(ts);
                    goto err;
                }
                ts->hash_len = prev->hash_len;
            }
            if (!subtrees_insert(new_subtrees, ts, &dup)) {
                subtree_free(ts);
                goto err; /* dup was excluded above, so this is a failure */
            }
        }
    }

    /*
     * Install the new window (creating the log only now, on success) and
     * repack the CA's precomputed advertisement to match; the repack cannot
     * fail.
     */
    if ((log = find_or_create_log(ca, log_number)) == NULL)
        goto err;
    old_subtrees = log->subtrees;
    log->subtrees = new_subtrees;
    new_subtrees = NULL;
    log->last_landmark = last_landmark;
    sk_OSSL_MTC_TRUSTED_SUBTREE_pop_free(old_subtrees, subtree_free);
    advertised_ids_repack(ca);
    ret = 1;
err:
    if (locked)
        CRYPTO_THREAD_unlock(ca->lock);
    sk_OSSL_MTC_TRUSTED_SUBTREE_pop_free(new_subtrees, subtree_free);
    OPENSSL_free(sizes);
    return ret;
}

int ossl_mtc_ca_add_subtree_hash(OSSL_MTC_CA *ca, uint64_t log_number,
    uint64_t start, uint64_t end, const uint8_t *hash, size_t hash_len)
{
    OSSL_MTC_LOG *log;
    OSSL_MTC_TRUSTED_SUBTREE *ts;
    uint8_t *hash_copy;
    int md_len, ret = 0;

    if (!CRYPTO_THREAD_write_lock(ca->lock))
        return 0;

    md_len = EVP_MD_get_size(ca->hash);
    if (md_len <= 0 || (size_t)md_len != hash_len)
        goto out; /* hash_len must match the log hash's output length */

    if ((log = find_log(ca, log_number)) == NULL)
        goto out;
    if ((ts = subtrees_find(log->subtrees, start, end)) == NULL)
        goto out; /* not in the active window */

    if (ts->hash != NULL) {
        /* A hash is immutable: the same value is a no-op, a different fails. */
        ret = ts->hash_len == hash_len && memcmp(ts->hash, hash, hash_len) == 0;
        goto out;
    }

    if ((hash_copy = OPENSSL_memdup(hash, hash_len)) == NULL)
        goto out;
    ts->hash = hash_copy;
    ts->hash_len = hash_len;
    /*
     * The new hash may change which landmark the CA advertises, so repack its
     * precomputed advertisement; the repack cannot fail.
     */
    advertised_ids_repack(ca);
    ret = 1;
out:
    CRYPTO_THREAD_unlock(ca->lock);
    return ret;
}

/*
 * Append one relative-OID component to pkt: big-endian base 128 with the
 * continuation bit set on all but the final octet.
 */
static int wpacket_put_reloid_component(WPACKET *pkt, uint64_t v)
{
    uint8_t tmp[10];
    size_t n = 0;

    do {
        tmp[n++] = (uint8_t)(v & 0x7f);
        v >>= 7;
    } while (v != 0);
    while (n-- > 0)
        if (!WPACKET_put_bytes_u8(pkt, tmp[n] | (n != 0 ? 0x80 : 0)))
            return 0;
    return 1;
}

/*
 * Repack the CA's precomputed advertisement (section 8.2.1) in place: one
 * u8-length-prefixed landmark group ID (the CA ID with 2, the log number, and
 * the newest vetted landmark appended) per log with a vetted landmark
 * subtree, or the bare CA ID when there is none.  The buffer is
 * grown when a log is added and the constructor bounds the CA ID, so the
 * packet operations cannot run out of room; their checks guard the
 * impossible, emptying the advertisement rather than leaving it stale.  The
 * caller holds the CA's write lock.
 */
static void advertised_ids_repack(OSSL_MTC_CA *ca)
{
    WPACKET pkt;
    size_t capacity, written = 0;
    int i, j, nlogs, groups = 0;

    nlogs = sk_OSSL_MTC_LOG_num(ca->logs); /* -1 when the stack is NULL */
    if (nlogs < 1)
        nlogs = 1; /* room for the bare CA ID */
    capacity = (size_t)nlogs * MTC_ADVERTISED_ID_SLOT;

    ca->advertised_ids_len = 0;
    if (!WPACKET_init_static_len(&pkt, ca->advertised_ids, capacity, 0))
        return;

    for (i = 0; i < sk_OSSL_MTC_LOG_num(ca->logs); i++) {
        OSSL_MTC_LOG *log = sk_OSSL_MTC_LOG_value(ca->logs, i);
        uint64_t newest = 0;
        int vetted = 0;

        for (j = 0; j < sk_OSSL_MTC_TRUSTED_SUBTREE_num(log->subtrees); j++) {
            OSSL_MTC_TRUSTED_SUBTREE *ts = sk_OSSL_MTC_TRUSTED_SUBTREE_value(log->subtrees, j);

            if (ts->hash == NULL)
                continue;
            if (!vetted || ts->landmark > newest)
                newest = ts->landmark;
            vetted = 1;
        }
        if (!vetted) /* nothing usable in this log yet */
            continue;

        if (!WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_memcpy(&pkt, ca->ca_id, ca->ca_id_len)
            || !wpacket_put_reloid_component(&pkt, 2)
            || !wpacket_put_reloid_component(&pkt, log->log_number)
            || !wpacket_put_reloid_component(&pkt, newest)
            || !WPACKET_close(&pkt))
            goto err;
        groups++;
    }

    /*
     * A group advertises standalone support too (it contains the CA ID
     * itself); only a CA with no group falls back to its bare CA ID.
     */
    if (groups == 0 && !WPACKET_sub_memcpy_u8(&pkt, ca->ca_id, ca->ca_id_len))
        goto err;

    if (!WPACKET_get_total_written(&pkt, &written) || !WPACKET_finish(&pkt))
        goto err;
    ca->advertised_ids_len = written;
    return;
err:
    WPACKET_cleanup(&pkt);
}

int ossl_mtc_ca_trusted_subtree_matches(const OSSL_MTC_CA *ca,
    uint64_t log_number, uint64_t start, uint64_t end, const uint8_t *hash,
    size_t hash_len, int *found)
{
    OSSL_MTC_LOG *log;
    OSSL_MTC_TRUSTED_SUBTREE *ts;
    int ret = 0;

    *found = 0;
    if (!CRYPTO_THREAD_read_lock(ca->lock))
        return 0;

    log = find_log(ca, log_number);
    /* An active subtree with no hash is not a trusted subtree (7.4). */
    if (log != NULL
        && (ts = subtrees_find(log->subtrees, start, end)) != NULL
        && ts->hash != NULL) {
        *found = 1;
        ret = ts->hash_len == hash_len
            && memcmp(ts->hash, hash, hash_len) == 0;
    }

    CRYPTO_THREAD_unlock(ca->lock);
    return ret;
}

int ossl_mtc_id_order(const uint8_t *a, size_t alen, const uint8_t *b,
    size_t blen)
{
    if (alen != blen)
        return alen < blen ? -1 : 1;
    return memcmp(a, b, alen);
}

int OSSL_MTC_CA_cmp(const OSSL_MTC_CA *const *a, const OSSL_MTC_CA *const *b)
{
    size_t alen, blen;
    const uint8_t *aid = ossl_mtc_ca_id(*a, &alen);
    const uint8_t *bid = ossl_mtc_ca_id(*b, &blen);

    return ossl_mtc_id_order(aid, alen, bid, blen);
}

int ossl_mtc_ca_stack_add(STACK_OF(OSSL_MTC_CA) *cas, OSSL_MTC_CA *ca)
{
    int idx = 0;

    if (sk_OSSL_MTC_CA_num(cas) > 0) {
        size_t alen, blen;
        const uint8_t *aid, *bid;
        int c;

        idx = sk_OSSL_MTC_CA_find_ex(cas, ca);
        aid = ossl_mtc_ca_id(sk_OSSL_MTC_CA_value(cas, idx), &alen);
        bid = ossl_mtc_ca_id(ca, &blen);
        c = ossl_mtc_id_order(aid, alen, bid, blen);
        if (c == 0)
            return 0; /* duplicate CA ID */
        if (c < 0)
            idx++;
    }
    return sk_OSSL_MTC_CA_insert(cas, ca, idx) > 0;
}

OSSL_MTC_CA *ossl_mtc_ca_stack_lookup(const STACK_OF(OSSL_MTC_CA) *cas,
    const uint8_t *ca_id, size_t ca_id_len)
{
    OSSL_MTC_CA key;
    int idx;

    memset(&key, 0, sizeof(key));
    key.ca_id = (uint8_t *)ca_id;
    key.ca_id_len = ca_id_len;
    idx = sk_OSSL_MTC_CA_find(cas, &key);
    return idx < 0 ? NULL : sk_OSSL_MTC_CA_value(cas, idx);
}

/* Public API. */

OSSL_MTC_CA *OSSL_MTC_CA_new(const uint8_t *ca_id, size_t ca_id_len,
    const EVP_MD *hash, uint64_t min_serial, EVP_PKEY *cosigner_pkey)
{
    if (ca_id == NULL || hash == NULL || cosigner_pkey == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return ossl_mtc_ca_new(ca_id, ca_id_len, hash, min_serial, cosigner_pkey);
}

void OSSL_MTC_CA_free(OSSL_MTC_CA *ca)
{
    ossl_mtc_ca_free(ca);
}

int OSSL_MTC_CA_add_revoked_range(OSSL_MTC_CA *ca, uint64_t start, uint64_t end)
{
    if (ca == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ossl_mtc_ca_add_revoked_range(ca, start, end);
}

OSSL_MTC_CA *OSSL_MTC_CA_find(STACK_OF(OSSL_MTC_CA) *cas, const uint8_t *ca_id,
    size_t ca_id_len, const char *ca_id_str)
{
    OSSL_MTC_CA *ca;
    uint8_t *wire = NULL;
    size_t wire_len = 0;

    if (cas == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (ca_id_str != NULL) {
        /* A malformed dotted-decimal string simply matches no CA. */
        if (!ossl_mtc_reloid_from_text(ca_id_str, strlen(ca_id_str), &wire,
                &wire_len))
            return NULL;
        ca = ossl_mtc_ca_stack_lookup(cas, wire, wire_len);
        OPENSSL_free(wire);
        return ca;
    }
    if (ca_id == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return ossl_mtc_ca_stack_lookup(cas, ca_id, ca_id_len);
}

int OSSL_MTC_CA_load_landmarks(OSSL_MTC_CA *ca, uint64_t log_number, BIO *in,
    int64_t cutoff)
{
    if (ca == NULL || in == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ossl_mtc_ca_load_landmarks(ca, log_number, in, cutoff);
}

int OSSL_MTC_CA_add_subtree_hash(OSSL_MTC_CA *ca, uint64_t log_number,
    uint64_t start, uint64_t end, const uint8_t *hash, size_t hash_len)
{
    if (ca == NULL || hash == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ossl_mtc_ca_add_subtree_hash(ca, log_number, start, end, hash,
        hash_len);
}

int OSSL_MTC_CA_set_max_serial(OSSL_MTC_CA *ca, uint64_t max_serial)
{
    if (ca == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ossl_mtc_ca_set_max_serial(ca, max_serial);
}

int OSSL_MTC_CA_get0_id(const OSSL_MTC_CA *ca, const uint8_t **out_id,
    size_t *out_id_len)
{
    if (ca == NULL || out_id == NULL || out_id_len == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *out_id = ossl_mtc_ca_id(ca, out_id_len);
    return 1;
}

uint64_t OSSL_MTC_serial(uint16_t log_number, uint64_t index)
{
    return ((uint64_t)log_number << 48) | index;
}
