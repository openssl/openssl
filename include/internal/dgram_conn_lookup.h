/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_DGRAM_CONN_LOOKUP_H
#define OSSL_INTERNAL_DGRAM_CONN_LOOKUP_H
#pragma once

#include <openssl/ssl.h>
#include "internal/dgram_demux.h"
#include "internal/queue.h"
#include "internal/hashtable.h"

#ifndef OPENSSL_NO_DTLS

/*
 * DGRAM_CONN_LOOKUP - Address-based connection lookup for DTLS
 * =============================================================
 *
 * This provides connection lookup by peer address (IP:port) for DTLS.
 * QUIC uses its own QUIC_LCIDM for CID-based lookup and does not use
 * this interface.
 *
 * The lookup uses the peer address from the DGRAM_URXE to find the
 * associated connection.
 */

/* The lookup is opaque: see ssl/dtls_conn_lookup.c. */
typedef struct dgram_conn_lookup_st DGRAM_CONN_LOOKUP;

/*
 * DGRAM_CONN_KEY - a peer address as the lookup hashes it
 *
 * Built and hashed once by ossl_dgram_conn_lookup_hash(), a key probes and
 * registers in that lookup and in every lookup created to share its hashing
 * key (see ossl_dgram_conn_lookup_new_addr()), so that a listener hashes
 * each datagram's source address once for both of its tables. The fields
 * are the lookup's own.
 *
 * The bytes of a key are the address family (int), the port (uint16_t) and
 * the raw address. A raw address is copied out of a BIO_ADDR, so it is never
 * longer than one.
 */
#define DGRAM_CONN_KEY_MAX_ADDR_LEN sizeof(BIO_ADDR)
#define DGRAM_CONN_KEY_MAX_LEN \
    (sizeof(int) + sizeof(uint16_t) + DGRAM_CONN_KEY_MAX_ADDR_LEN)
typedef struct dgram_conn_key_st {
    unsigned char buf[DGRAM_CONN_KEY_MAX_LEN];
    size_t len;
    uint64_t hash;
    uint64_t hashed_with; /* identifies the hashing key, for checking */
} DGRAM_CONN_KEY;

/*
 * DGRAM_CONN_LINK - per-connection membership of a lookup table
 *
 * A connection is linked into the table through this structure. It is part
 * of the block a connection is given the first time it is registered
 * (DTLS_LISTENER_CONN, SSL_CONNECTION.listener_conn) and keeps until it is
 * freed, so a connection that is never registered does not pay for it, and
 * the lookup allocates nothing for a connection it has seen before: moving
 * one from a lookup to another cannot fail for want of memory. A connection
 * can be registered in at most one lookup at a time; |lookup| records which,
 * so that unregistering it never depends on its current peer address. The
 * table does not own the connection, and the link names it through the block
 * it is contained in rather than by a pointer of its own. Besides its hash
 * bucket, a registered link is also on the lookup's list of all entries, in
 * registration order, so that iteration costs the number of connections
 * rather than the number of buckets, and can stop early.
 */
typedef struct dgram_conn_link_st {
    OSSL_HTABLE_MEMBER(addr); /* bucket link + keyed hash of |peer| */
    OSSL_QUEUE_MEMBER(addr_all);
    DGRAM_CONN_LOOKUP *lookup; /* the lookup it is registered in, else NULL */
    BIO_ADDR peer; /* the address it was registered under */
} DGRAM_CONN_LINK;

/*
 * Callback type for iterating over connections. They are visited in the
 * order they were registered, oldest first.
 */
typedef void (*ossl_dgram_conn_lookup_iter_fn)(SSL *ssl, const BIO_ADDR *peer,
    void *arg);

/*
 * Callback type for an iteration that can end early: as above, until the
 * callback returns 0. The entries of a pending table share one deadline, so
 * an expiry walk over it stops at the first entry that is not due.
 */
typedef int (*ossl_dgram_conn_lookup_until_fn)(SSL *ssl, const BIO_ADDR *peer,
    void *arg);

/**
 * Create an address-based lookup (DTLS). A lookup hashes with a random key
 * of its own, or, given |share|, with that lookup's key, so that a
 * DGRAM_CONN_KEY hashed by either is good for both. Its table starts sized
 * for |expected| entries (0 for the minimum) and grows as needed.
 *
 * @param share    a lookup whose hashing key to reuse, or NULL to draw a
 *                 fresh random key
 * @param expected the number of entries to size the table for, 0 for the
 *                 minimum
 * @returns the new lookup, or NULL on allocation or RAND failure
 */
DGRAM_CONN_LOOKUP *ossl_dgram_conn_lookup_new_addr(const DGRAM_CONN_LOOKUP *share,
    size_t expected);

/*
 * Find or register a connection by peer address, hashing it on the way. The
 * first registration of a connection allocates its link and can fail for
 * that; see DGRAM_CONN_LINK.
 */
SSL *ossl_dgram_conn_lookup_find(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_URXE *e);
int ossl_dgram_conn_lookup_register_addr(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer,
    SSL *ssl);
/*
 * The same by a key: hashed once from |peer| for every lookup sharing the
 * hashing key of the one that hashed it. The |peer| registered must be the
 * address the key was hashed from.
 */

/**
 * Build and hash the key for |peer|, good for |lookup| and for every lookup
 * sharing its hashing key.
 *
 * @param lookup the lookup whose hashing key to use
 * @param peer   the peer address to hash
 * @param key    receives the built and hashed key
 * @returns 1 on success, 0 if |lookup| is NULL or the address cannot be
 *          represented in a key
 */
int ossl_dgram_conn_lookup_hash(const DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer, DGRAM_CONN_KEY *key);

/**
 * Find the connection registered under a hashed key.
 *
 * @param lookup the lookup to search
 * @param key    a key hashed by ossl_dgram_conn_lookup_hash() with |lookup|
 *               or a lookup sharing its hashing key
 * @returns the registered connection, or NULL if there is none
 */
SSL *ossl_dgram_conn_lookup_find_key(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key);

/**
 * Register a connection under a hashed key. The lookup does not take
 * ownership of |ssl|. Registering a peer that is already present, or a
 * connection that is already registered in a lookup, is refused. The first
 * registration of a connection allocates its link; later ones do not.
 *
 * @param lookup the lookup to register in
 * @param key    a key hashed from |peer| by ossl_dgram_conn_lookup_hash()
 *               with |lookup| or a lookup sharing its hashing key
 * @param peer   the address |key| was hashed from
 * @param ssl    the connection to register
 * @returns 1 on success, 0 on failure
 */
int ossl_dgram_conn_lookup_register_key(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_CONN_KEY *key,
    const BIO_ADDR *peer, SSL *ssl);

/**
 * Unlink |ssl| from the lookup it is registered in, if any, whatever its
 * current peer address. Not being registered is not an error: a connection
 * being freed calls this unconditionally. The caller must hold the lock that
 * serialises access to that lookup.
 *
 * @param ssl the connection to unlink
 * @returns 1 if it was registered, 0 if it was not
 */
int ossl_dgram_conn_lookup_unregister(SSL *ssl);
void ossl_dgram_conn_lookup_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb,
    void *arg);
void ossl_dgram_conn_lookup_foreach_until(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_until_fn cb,
    void *arg);
void ossl_dgram_conn_lookup_free(DGRAM_CONN_LOOKUP *lookup);
size_t ossl_dgram_conn_lookup_num_items(const DGRAM_CONN_LOOKUP *lookup);

#endif /* OPENSSL_NO_DTLS */
#endif /* OSSL_INTERNAL_DGRAM_CONN_LOOKUP_H */
