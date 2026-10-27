/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include "ssl_local.h"
#include "internal/ssl_unwrap.h"
#include "internal/common.h"
#include "internal/dgram_conn_lookup.h"
#include "internal/queue.h"
#include "crypto/siphash.h"

#ifndef OPENSSL_NO_DTLS

/*
 * Address-based lookup. Connections are linked into intrusive hash buckets
 * through the DGRAM_CONN_LINK embedded in their DTLS state, so neither
 * registration nor lookup allocates. The bucket array is sized when the
 * lookup is created, from the number of entries its owner expects, and
 * doubles whenever the entries outnumber the buckets, so chains stay short
 * at any size while a listener's tables start at a few hundred bytes
 * rather than 128 KB each: its pending table holds at most
 * max_pending_conns entries, 256 by default, and its established table has
 * no bound. Every link carries its hash, so growing re-links the entries
 * without hashing them; a table never shrinks. Every registered link is
 * also on the |all| list, in registration order, which iteration walks
 * instead of the buckets: the listener expires a pending table from its
 * oldest entry and stops at the first one that is not due, so a tick walks
 * neither the buckets nor the entries behind it.
 */
#define ADDR_LOOKUP_MIN_BITS 6 /* 64 buckets, 512 bytes on LP64 */
#define ADDR_LOOKUP_MAX_BITS 20 /* 1M buckets, 8 MB */

DEFINE_QUEUE_OF(addr, DGRAM_CONN_LINK);
DEFINE_QUEUE_OF(addr_all, DGRAM_CONN_LINK);

typedef struct addr_lookup_data_st {
    OSSL_QUEUE *buckets; /* 1 << bits of them */
    unsigned int bits;
    size_t num; /* entries currently registered */
    OSSL_QUEUE all; /* every registered link, oldest registration first */
    DGRAM_CONN_LINK *last; /* the newest, i.e. the tail of |all|, or NULL */
    uint64_t hash_key[2]; /* 128-bit SipHash key (hash-flooding defense) */
} ADDR_LOOKUP_DATA;

static size_t addr_num_buckets(const ADDR_LOOKUP_DATA *data)
{
    return (size_t)1 << data->bits;
}

static OSSL_QUEUE *addr_bucket(const ADDR_LOOKUP_DATA *data, uint64_t hash)
{
    return &data->buckets[hash & (addr_num_buckets(data) - 1)];
}

static OSSL_QUEUE *addr_buckets_new(unsigned int bits)
{
    size_t i, n = (size_t)1 << bits;
    OSSL_QUEUE *buckets = OPENSSL_malloc(n * sizeof(*buckets));

    if (buckets == NULL)
        return NULL;
    for (i = 0; i < n; i++)
        ossl_queue_init(&buckets[i]);
    return buckets;
}

/*
 * Double the buckets, re-linking every entry by the hash it carries. On
 * allocation failure the table carries on with its longer chains and tries
 * again at the next registration.
 */
static void addr_grow(ADDR_LOOKUP_DATA *data)
{
    OSSL_QUEUE *buckets;
    DGRAM_CONN_LINK *link;
    uint64_t mask;

    if (data->bits >= ADDR_LOOKUP_MAX_BITS
        || (buckets = addr_buckets_new(data->bits + 1)) == NULL)
        return;

    mask = ((uint64_t)1 << (data->bits + 1)) - 1;
    OSSL_QUEUE_FOREACH (link, addr_all, &data->all) {
        /* The old buckets are discarded whole, so the old links need no unlinking */
        ossl_queue_addr_init_elem(link);
        ossl_queue_addr_add(&buckets[link->hash & mask], link);
    }
    OPENSSL_free(data->buckets);
    data->buckets = buckets;
    data->bits++;
}

/*
 * The bytes of a key, derived from a BIO_ADDR: family (int) + port
 * (uint16_t) + raw address bytes.
 */
static int addr_key_build(const BIO_ADDR *peer, DGRAM_CONN_KEY *key)
{
    int family = BIO_ADDR_family(peer);
    uint16_t port;
    size_t addr_len = 0;
    unsigned char *p = key->buf;

    memcpy(p, &family, sizeof(family));
    p += sizeof(family);

    /* For AF_UNSPEC (no peer address), use a minimal key */
    if (family == AF_UNSPEC) {
        key->len = sizeof(family);
        return 1;
    }

    if (!BIO_ADDR_rawaddress(peer, NULL, &addr_len)
        || addr_len > DGRAM_CONN_KEY_MAX_ADDR_LEN)
        return 0;

    port = BIO_ADDR_rawport(peer);
    memcpy(p, &port, sizeof(port));
    p += sizeof(port);

    if (!BIO_ADDR_rawaddress(peer, p, NULL))
        return 0;

    key->len = sizeof(family) + sizeof(port) + addr_len;
    return 1;
}

/*
 * Keyed hash of a built key. SipHash with a per-lookup random key defends
 * against hash-flooding CPU DoS attacks. The key records which hashing key
 * it was hashed with, and every lookup it is used with checks that.
 */
static int addr_key_hash(const ADDR_LOOKUP_DATA *data, DGRAM_CONN_KEY *key)
{
    SIPHASH siphash = { 0 };
    unsigned char digest[SIPHASH_MIN_DIGEST_SIZE];

    if (!SipHash_set_hash_size(&siphash, SIPHASH_MIN_DIGEST_SIZE)
        || !SipHash_Init(&siphash, (const unsigned char *)data->hash_key, 0, 0))
        return 0;
    SipHash_Update(&siphash, key->buf, key->len);
    if (!SipHash_Final(&siphash, digest, sizeof(digest)))
        return 0;

    memcpy(&key->hash, digest, sizeof(key->hash));
    key->hashed_with = data->hash_key[0];
    return 1;
}

static int addr_key_matches(const ADDR_LOOKUP_DATA *data,
    const DGRAM_CONN_KEY *key)
{
    return key->hashed_with == data->hash_key[0];
}

/* Find the link registered under the hashed |key|. */
static DGRAM_CONN_LINK *addr_find_key(const ADDR_LOOKUP_DATA *data,
    const DGRAM_CONN_KEY *key)
{
    DGRAM_CONN_LINK *link;
    DGRAM_CONN_KEY ckey;

    OSSL_QUEUE_FOREACH (link, addr, addr_bucket(data, key->hash))
        if (link->hash == key->hash
            && addr_key_build(&link->peer, &ckey)
            && ckey.len == key->len
            && memcmp(ckey.buf, key->buf, key->len) == 0)
            break;
    return link;
}

/* Build and hash |peer| for this lookup and those sharing its hashing key. */
static int addr_hash(const DGRAM_CONN_LOOKUP *lookup, const BIO_ADDR *peer,
    DGRAM_CONN_KEY *key)
{
    if (lookup == NULL || lookup->impl_data == NULL || peer == NULL
        || key == NULL)
        return 0;
    return addr_key_build(peer, key) && addr_key_hash(lookup->impl_data, key);
}

/* The link embedded in a connection, or NULL if |ssl| is not a connection. */
static DGRAM_CONN_LINK *conn_link_of(SSL *ssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (sc == NULL)
        return NULL;
    return &sc->listener_lookup_link;
}

/*
 * Lookup a connection by a hashed key.
 */
static SSL *addr_lookup_key(DGRAM_CONN_LOOKUP *lookup, const DGRAM_CONN_KEY *key)
{
    const ADDR_LOOKUP_DATA *data;
    DGRAM_CONN_LINK *link;

    if (lookup == NULL || (data = lookup->impl_data) == NULL || key == NULL
        || !ossl_assert(addr_key_matches(data, key)))
        return NULL;

    link = addr_find_key(data, key);
    return link == NULL ? NULL : link->ssl;
}

/*
 * Lookup a connection by peer address from URXE.
 */
static SSL *addr_lookup(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e)
{
    DGRAM_CONN_KEY key;

    if (e == NULL || !addr_hash(lookup, &e->peer, &key))
        return NULL;
    return addr_lookup_key(lookup, &key);
}

/*
 * Register a connection under a hashed key, |peer| being the address the key
 * was hashed from.
 *
 * Callers always look up an address and only register when no entry exists,
 * all while holding the listener mutex, so the same peer is never registered
 * twice; a connection is likewise never registered in two lookups at once.
 * Both are checked and refused rather than silently replacing an entry.
 *
 * The lookup is an ownership-agnostic index: it never frees the SSL objects
 * it stores. The owning layer (the DTLS listener) manages their lifecycle.
 */
static int addr_register_key(DGRAM_CONN_LOOKUP *lookup, const DGRAM_CONN_KEY *key,
    const BIO_ADDR *peer, SSL *ssl)
{
    ADDR_LOOKUP_DATA *data;
    DGRAM_CONN_LINK *link;

    if (lookup == NULL || (data = lookup->impl_data) == NULL || key == NULL
        || peer == NULL || ssl == NULL)
        return 0;
    if (!ossl_assert(addr_key_matches(data, key)))
        return 0;

    if ((link = conn_link_of(ssl)) == NULL)
        return 0;
    if (!ossl_assert(!ossl_queue_addr_hashed(link)))
        return 0;
    if (!ossl_assert(addr_find_key(data, key) == NULL))
        return 0;

    link->lookup = lookup;
    link->hash = key->hash;
    link->ssl = ssl;
    BIO_ADDR_copy(&link->peer, peer);
    ossl_queue_addr_add(addr_bucket(data, key->hash), link);
    /* Append: |all| is kept in registration order. */
    if (data->last == NULL)
        ossl_queue_addr_all_add(&data->all, link);
    else
        ossl_queue_addr_all_add_behind(link, data->last);
    data->last = link;
    if (++data->num > addr_num_buckets(data))
        addr_grow(data);
    return 1;
}

/*
 * Register a connection by peer address.
 */
static int addr_register_conn_addr(DGRAM_CONN_LOOKUP *lookup, const BIO_ADDR *peer,
    SSL *ssl)
{
    DGRAM_CONN_KEY key;

    if (!addr_hash(lookup, peer, &key))
        return 0;
    return addr_register_key(lookup, &key, peer, ssl);
}

static void addr_unlink(ADDR_LOOKUP_DATA *data, DGRAM_CONN_LINK *link)
{
    ossl_queue_addr_del(link);
    data->num--;
    if (link == data->last)
        data->last = ossl_queue_addr_all_prev(&data->all, link);
    ossl_queue_addr_all_del(link);
    link->ssl = NULL;
    link->lookup = NULL;
}

/*
 * Unregister a connection. It is unlinked through its own node, so this
 * neither rebuilds nor hashes an address and cannot miss: the connection's
 * peer address may have changed since it was registered.
 */
static int addr_unregister_conn(DGRAM_CONN_LOOKUP *lookup, SSL *ssl)
{
    DGRAM_CONN_LINK *link;

    if (lookup == NULL || lookup->impl_data == NULL
        || (link = conn_link_of(ssl)) == NULL)
        return 0;
    if (!ossl_assert(link->lookup == lookup && ossl_queue_addr_hashed(link)))
        return 0;

    addr_unlink(lookup->impl_data, link);
    return 1;
}

/*
 * Free the lookup structure. Connections still registered are unlinked so
 * that they can be registered elsewhere; they are not freed.
 */
static void addr_free(DGRAM_CONN_LOOKUP *lookup)
{
    ADDR_LOOKUP_DATA *data;
    DGRAM_CONN_LINK *link, *next;

    if (lookup == NULL)
        return;

    if ((data = lookup->impl_data) != NULL) {
        OSSL_QUEUE_FOREACH_DELSAFE (link, next, addr_all, &data->all)
            addr_unlink(data, link);
        OPENSSL_free(data->buckets);
        OPENSSL_free(data);
    }

    OPENSSL_free(lookup);
}

/*
 * Iterate over all connections, oldest registration first, calling the
 * callback for each until it returns 0. The callback may unregister (and
 * then free) the connection it is handed, but no other.
 */
static void addr_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb, void *arg)
{
    ADDR_LOOKUP_DATA *data;
    DGRAM_CONN_LINK *link, *next;

    if (lookup == NULL || lookup->impl_data == NULL || cb == NULL)
        return;

    data = lookup->impl_data;
    OSSL_QUEUE_FOREACH_DELSAFE (link, next, addr_all, &data->all) {
        /*
         * The list is a dependent pointer chase through connections that
         * are cold at large counts; fetching the next one while the callback
         * works on this one overlaps the misses.
         */
#if defined(__GNUC__) || defined(__clang__)
        if (next != NULL)
            __builtin_prefetch(next);
#endif
        if (!cb(link->ssl, &link->peer, arg))
            break;
    }
}

static size_t addr_num_items(const DGRAM_CONN_LOOKUP *lookup)
{
    const ADDR_LOOKUP_DATA *data;

    if (lookup == NULL || lookup->impl_data == NULL)
        return 0;

    data = lookup->impl_data;
    return data->num;
}

static const DGRAM_CONN_LOOKUP_METHODS addr_methods = {
    addr_hash,
    addr_lookup,
    addr_lookup_key,
    addr_register_conn_addr,
    addr_register_key,
    addr_unregister_conn,
    addr_foreach,
    addr_free,
    addr_num_items
};

/*
 * Create a new address-based connection lookup for DTLS. With |share|, it
 * hashes with that lookup's key instead of one of its own, so that a key
 * hashed by either probes and registers in both: the listener hashes each
 * datagram's peer address once for its two tables. The buckets start at
 * the smallest power of two not below |expected|, within the bounds, and
 * double whenever the entries outnumber them.
 */
DGRAM_CONN_LOOKUP *ossl_dgram_conn_lookup_new_addr(const DGRAM_CONN_LOOKUP *share,
    size_t expected)
{
    DGRAM_CONN_LOOKUP *lookup;
    ADDR_LOOKUP_DATA *data;
    unsigned int bits = ADDR_LOOKUP_MIN_BITS;

    while (bits < ADDR_LOOKUP_MAX_BITS && ((size_t)1 << bits) < expected)
        bits++;

    lookup = OPENSSL_zalloc(sizeof(*lookup));
    if (lookup == NULL)
        return NULL;

    data = OPENSSL_zalloc(sizeof(*data));
    if (data == NULL) {
        OPENSSL_free(lookup);
        return NULL;
    }

    if (share != NULL) {
        if (share->methods != &addr_methods || share->impl_data == NULL) {
            OPENSSL_free(data);
            OPENSSL_free(lookup);
            return NULL;
        }
        memcpy(data->hash_key,
            ((const ADDR_LOOKUP_DATA *)share->impl_data)->hash_key,
            sizeof(data->hash_key));
    } else if (RAND_priv_bytes((unsigned char *)data->hash_key,
                   sizeof(data->hash_key))
        <= 0) {
        /* Random SipHash key for hash-flooding defense: none, no lookup */
        OPENSSL_free(data);
        OPENSSL_free(lookup);
        return NULL;
    }
    if ((data->buckets = addr_buckets_new(bits)) == NULL) {
        OPENSSL_free(data);
        OPENSSL_free(lookup);
        return NULL;
    }
    data->bits = bits;
    ossl_queue_init(&data->all);

    lookup->methods = &addr_methods;
    lookup->impl_data = data;

    return lookup;
}

/*
 * Public API wrappers - call through methods table.
 */
SSL *ossl_dgram_conn_lookup_find(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->lookup == NULL)
        return NULL;
    return lookup->methods->lookup(lookup, e);
}

int ossl_dgram_conn_lookup_register_addr(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer, SSL *ssl)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->register_conn_addr == NULL)
        return 0;
    return lookup->methods->register_conn_addr(lookup, peer, ssl);
}

int ossl_dgram_conn_lookup_hash(const DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer, DGRAM_CONN_KEY *key)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->hash == NULL)
        return 0;
    return lookup->methods->hash(lookup, peer, key);
}

SSL *ossl_dgram_conn_lookup_find_key(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->lookup_key == NULL)
        return NULL;
    return lookup->methods->lookup_key(lookup, key);
}

int ossl_dgram_conn_lookup_register_key(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key, const BIO_ADDR *peer, SSL *ssl)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->register_key == NULL)
        return 0;
    return lookup->methods->register_key(lookup, key, peer, ssl);
}

int ossl_dgram_conn_lookup_unregister(SSL *ssl)
{
    DGRAM_CONN_LINK *link = conn_link_of(ssl);
    DGRAM_CONN_LOOKUP *lookup;

    if (link == NULL || (lookup = link->lookup) == NULL
        || lookup->methods == NULL || lookup->methods->unregister_conn == NULL)
        return 0;
    return lookup->methods->unregister_conn(lookup, ssl);
}

void ossl_dgram_conn_lookup_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb, void *arg)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->foreach == NULL)
        return;
    lookup->methods->foreach(lookup, cb, arg);
}

void ossl_dgram_conn_lookup_free(DGRAM_CONN_LOOKUP *lookup)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->free == NULL)
        return;
    lookup->methods->free(lookup);
}

/*
 * Return the number of entries currently registered.
 *
 * The lookup is not internally synchronised: like the other lookup
 * operations, the caller must hold the lock that serialises access to it.
 * Reading the count without that lock held races with concurrent
 * register/unregister.
 */
size_t ossl_dgram_conn_lookup_num_items(const DGRAM_CONN_LOOKUP *lookup)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->num_items == NULL)
        return 0;
    return lookup->methods->num_items(lookup);
}

#endif /* OPENSSL_NO_DTLS */
