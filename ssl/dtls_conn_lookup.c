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
#include "internal/htable.h"

#ifndef OPENSSL_NO_DTLS

/*
 * Address-based lookup. Connections are linked into a growable intrusive
 * hash table (internal/htable.h) through a DGRAM_CONN_LINK, part of the
 * block a connection is given at its first registration and keeps for its
 * lifetime (DTLS_LISTENER_CONN). Apart from that, neither registration nor
 * lookup allocates, except when the table doubles its buckets because the
 * entries outnumber them. The buckets start in the lookup itself and are
 * grown up front, when the lookup is created, for the number of entries its
 * owner expects, so a listener's tables start at a few hundred bytes rather
 * than 128 KB each: its pending table holds at most max_pending_conns
 * entries, 256 by default, and its established table has no bound. Every
 * link carries its hash, so growing re-links the entries without hashing
 * them, an O(n) step at each power of two under the lock the caller holds; a
 * table never shrinks. Every registered link is also on the |all| list, in
 * registration order, which iteration walks instead of the buckets: the
 * listener expires a pending table from its oldest entry and stops at the
 * first one that is not due, so a tick walks neither the buckets nor the
 * entries behind it.
 */
#define ADDR_LOOKUP_MIN_BITS 6 /* 64 buckets, 512 bytes on LP64 */
#define ADDR_LOOKUP_MAX_BITS 20 /* 1M buckets, 8 MB */

DEFINE_QUEUE_OF(addr, DGRAM_CONN_LINK);
DEFINE_HTABLE_DYN_OF(addr, DGRAM_CONN_LINK, ADDR_LOOKUP_MIN_BITS,
    ADDR_LOOKUP_MAX_BITS);
DEFINE_QUEUE_OF(addr_all, DGRAM_CONN_LINK);

struct dgram_conn_lookup_st {
    OSSL_HTABLE(addr) table; /* by keyed hash of the peer address */
    OSSL_QUEUE all; /* every registered link, oldest registration first */
    DGRAM_CONN_LINK *last; /* the newest, i.e. the tail of |all|, or NULL */
    uint64_t hash_key[2]; /* 128-bit SipHash key (hash-flooding defense) */
};

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
static void addr_key_hash(const DGRAM_CONN_LOOKUP *lookup, DGRAM_CONN_KEY *key)
{
    key->hash = ossl_siphash24_u64((const unsigned char *)lookup->hash_key,
        key->buf, key->len);
    key->hashed_with = lookup->hash_key[0];
}

static int addr_key_matches(const DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key)
{
    return key->hashed_with == lookup->hash_key[0];
}

/* Find the link registered under the hashed |key|. */
static DGRAM_CONN_LINK *addr_find_key(const DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key)
{
    DGRAM_CONN_LINK *link;
    DGRAM_CONN_KEY ckey;

    OSSL_HTABLE_FIND(link, addr, &lookup->table, key->hash,
        addr_key_build(&link->peer, &ckey)
            && ckey.len == key->len
            && memcmp(ckey.buf, key->buf, key->len) == 0);
    return link;
}

/*
 * The link of a connection, or NULL if |ssl| is not a connection or has no
 * link. With |create|, a connection that has none is given the block that
 * holds it, which it keeps until it is freed; NULL then also means that the
 * allocation failed.
 */
static DGRAM_CONN_LINK *conn_link_of(SSL *ssl, int create)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (sc == NULL)
        return NULL;

    if (sc->listener_conn == NULL) {
        if (!create)
            return NULL;
        sc->listener_conn = OPENSSL_zalloc(sizeof(*sc->listener_conn));
        if (sc->listener_conn == NULL)
            return NULL;
        sc->listener_conn->sc = sc;
    }
    return &sc->listener_conn->lookup_link;
}

/* The connection a link belongs to. */
static SSL *link_conn(DGRAM_CONN_LINK *link)
{
    DTLS_LISTENER_CONN *lc
        = OSSL_CONTAINER_OF(link, DTLS_LISTENER_CONN, lookup_link);

    return SSL_CONNECTION_GET_SSL(lc->sc);
}

static void addr_unlink(DGRAM_CONN_LOOKUP *lookup, DGRAM_CONN_LINK *link)
{
    ossl_htable_addr_del(&lookup->table, link);
    ossl_queue_addr_all_del_keep_tail(&lookup->all, &lookup->last, link);
    link->lookup = NULL;
}

/*
 * Create a new address-based connection lookup for DTLS. With |share|, it
 * hashes with that lookup's key instead of one of its own, so that a key
 * hashed by either probes and registers in both: the listener hashes each
 * datagram's peer address once for its two tables. The buckets start at
 * the smallest power of two not below |expected|, within the bounds (or
 * fewer, if growing them for |expected| fails), and double whenever the
 * entries outnumber them.
 */
DGRAM_CONN_LOOKUP *ossl_dgram_conn_lookup_new_addr(const DGRAM_CONN_LOOKUP *share,
    size_t expected)
{
    DGRAM_CONN_LOOKUP *lookup;

    lookup = OPENSSL_zalloc(sizeof(*lookup));
    if (lookup == NULL)
        return NULL;

    if (share != NULL) {
        memcpy(lookup->hash_key, share->hash_key, sizeof(lookup->hash_key));
    } else if (RAND_priv_bytes((unsigned char *)lookup->hash_key,
                   sizeof(lookup->hash_key))
        <= 0) {
        /* Random SipHash key for hash-flooding defense: none, no lookup */
        OPENSSL_free(lookup);
        return NULL;
    }
    ossl_htable_addr_init(&lookup->table);
    /* Best effort: a table that could not grow up front grows as it fills. */
    (void)ossl_htable_addr_reserve(&lookup->table, expected);
    ossl_queue_init(&lookup->all);

    return lookup;
}

/* Build and hash |peer| for this lookup and those sharing its hashing key. */
int ossl_dgram_conn_lookup_hash(const DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer, DGRAM_CONN_KEY *key)
{
    if (lookup == NULL || peer == NULL || key == NULL
        || !addr_key_build(peer, key))
        return 0;

    addr_key_hash(lookup, key);
    return 1;
}

/*
 * Lookup a connection by a hashed key.
 */
SSL *ossl_dgram_conn_lookup_find_key(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key)
{
    DGRAM_CONN_LINK *link;

    if (lookup == NULL || key == NULL
        || !ossl_assert(addr_key_matches(lookup, key)))
        return NULL;

    link = addr_find_key(lookup, key);
    return link == NULL ? NULL : link_conn(link);
}

/*
 * Lookup a connection by peer address from URXE.
 */
SSL *ossl_dgram_conn_lookup_find(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e)
{
    DGRAM_CONN_KEY key;

    if (e == NULL || !ossl_dgram_conn_lookup_hash(lookup, &e->peer, &key))
        return NULL;
    return ossl_dgram_conn_lookup_find_key(lookup, &key);
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
int ossl_dgram_conn_lookup_register_key(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key, const BIO_ADDR *peer, SSL *ssl)
{
    DGRAM_CONN_LINK *link;

    if (lookup == NULL || key == NULL || peer == NULL || ssl == NULL)
        return 0;
    if (!ossl_assert(addr_key_matches(lookup, key)))
        return 0;
    if (!ossl_assert(addr_find_key(lookup, key) == NULL))
        return 0;

    /* Allocates the link the first time this connection is registered. */
    if ((link = conn_link_of(ssl, 1)) == NULL)
        return 0;
    if (!ossl_assert(!ossl_queue_addr_hashed(link)))
        return 0;

    link->lookup = lookup;
    BIO_ADDR_copy(&link->peer, peer);
    ossl_htable_addr_add(&lookup->table, link, key->hash);
    /* Append: |all| is kept in registration order. */
    ossl_queue_addr_all_add_tail(&lookup->all, &lookup->last, link);
    return 1;
}

/*
 * Register a connection by peer address.
 */
int ossl_dgram_conn_lookup_register_addr(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer, SSL *ssl)
{
    DGRAM_CONN_KEY key;

    if (!ossl_dgram_conn_lookup_hash(lookup, peer, &key))
        return 0;
    return ossl_dgram_conn_lookup_register_key(lookup, &key, peer, ssl);
}

/*
 * Unregister a connection. It is unlinked through its own node, so this
 * neither rebuilds nor hashes an address and cannot miss: the connection's
 * peer address may have changed since it was registered.
 */
int ossl_dgram_conn_lookup_unregister(SSL *ssl)
{
    DGRAM_CONN_LINK *link = conn_link_of(ssl, 0);

    if (link == NULL || link->lookup == NULL)
        return 0;
    if (!ossl_assert(ossl_queue_addr_hashed(link)))
        return 0;

    addr_unlink(link->lookup, link);
    return 1;
}

/*
 * Iterate over all connections, oldest registration first, calling the
 * callback for each until it returns 0. The callback may unregister (and
 * then free) the connection it is handed, but no other.
 */
void ossl_dgram_conn_lookup_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb, void *arg)
{
    DGRAM_CONN_LINK *link, *next;

    if (lookup == NULL || cb == NULL)
        return;

    OSSL_QUEUE_FOREACH_DELSAFE (link, next, addr_all, &lookup->all) {
        /*
         * The list is a dependent pointer chase through links that are
         * cold at large counts; fetching the next one while the callback
         * works on this one overlaps the misses.
         */
#if defined(__GNUC__) || defined(__clang__)
        if (next != NULL)
            __builtin_prefetch(next);
#endif
        if (!cb(link_conn(link), &link->peer, arg))
            break;
    }
}

/*
 * Free the lookup structure. Connections still registered are unlinked so
 * that they can be registered elsewhere; they are not freed.
 */
void ossl_dgram_conn_lookup_free(DGRAM_CONN_LOOKUP *lookup)
{
    DGRAM_CONN_LINK *link, *next;

    if (lookup == NULL)
        return;

    OSSL_QUEUE_FOREACH_DELSAFE (link, next, addr_all, &lookup->all)
        addr_unlink(lookup, link);
    ossl_htable_addr_cleanup(&lookup->table);
    OPENSSL_free(lookup);
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
    return lookup == NULL ? 0 : ossl_htable_num(&lookup->table);
}

#endif /* OPENSSL_NO_DTLS */
