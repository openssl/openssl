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
#include "internal/dgram_conn_lookup.h"
#include "internal/hashfunc.h"

#ifndef OPENSSL_NO_DTLS

/*
 * Internal entry structure for address-based connection lookup.
 * Stores a connection keyed by peer address.
 */
typedef struct dgram_conn_entry_st {
    BIO_ADDR peer; /* Peer address (key) */
    SSL *ssl; /* The SSL connection object */
    uint8_t *hashkey; /* Pre-built hash key (family + port + addr) */
    size_t hashkey_len; /* Length of the hash key */
} DGRAM_CONN_ENTRY;

DEFINE_LHASH_OF_EX(DGRAM_CONN_ENTRY);

/*
 * Build a hash key from a BIO_ADDR.
 * The key format is: family (int) + port (uint16_t) + raw address bytes.
 *
 * Returns allocated hashkey buffer on success, NULL on failure.
 */
static uint8_t *build_hashkey(const BIO_ADDR *peer, size_t *out_len)
{
    size_t hashkey_len = 0;
    size_t addr_len = 0;
    int family;
    uint16_t port;
    uint8_t *hashkey;
    int *famptr;
    uint16_t *portptr;
    uint8_t *addrptr;

    family = BIO_ADDR_family(peer);

    /* For AF_UNSPEC (no peer address), use a minimal key */
    if (family == AF_UNSPEC) {
        hashkey_len = sizeof(int);
        hashkey = OPENSSL_zalloc(hashkey_len);
        if (hashkey == NULL)
            return NULL;
        famptr = (int *)hashkey;
        *famptr = family;
        *out_len = hashkey_len;
        return hashkey;
    }

    if (!BIO_ADDR_rawaddress(peer, NULL, &addr_len))
        return NULL;

    port = BIO_ADDR_rawport(peer);

    hashkey_len += sizeof(int); /* family */
    hashkey_len += sizeof(uint16_t); /* port */
    hashkey_len += addr_len; /* address */

    hashkey = OPENSSL_zalloc(hashkey_len);
    if (hashkey == NULL)
        return NULL;

    famptr = (int *)hashkey;
    portptr = (uint16_t *)(famptr + 1);
    addrptr = (uint8_t *)(portptr + 1);

    *famptr = family;
    *portptr = port;
    if (!BIO_ADDR_rawaddress(peer, addrptr, NULL)) {
        OPENSSL_free(hashkey);
        return NULL;
    }

    *out_len = hashkey_len;
    return hashkey;
}

/*
 * Hash function for DGRAM_CONN_ENTRY - uses pre-built hashkey.
 */
static unsigned long conn_entry_hash(const DGRAM_CONN_ENTRY *e)
{
    if (e->hashkey == NULL || e->hashkey_len == 0)
        return 0;

    return (unsigned long)ossl_fnv1a_hash(e->hashkey, e->hashkey_len);
}

/*
 * Compare function for DGRAM_CONN_ENTRY - compares pre-built hashkeys.
 * Returns 0 if equal, non-zero otherwise.
 */
static int conn_entry_cmp(const DGRAM_CONN_ENTRY *a, const DGRAM_CONN_ENTRY *b)
{
    if (a->hashkey_len != b->hashkey_len)
        return 1;
    if (a->hashkey == NULL || b->hashkey == NULL)
        return (a->hashkey == b->hashkey) ? 0 : 1;
    return memcmp(a->hashkey, b->hashkey, a->hashkey_len);
}

/*
 * Free a connection entry (but not the connection itself).
 */
static void conn_entry_free(DGRAM_CONN_ENTRY *e)
{
    if (e == NULL)
        return;
    OPENSSL_free(e->hashkey);
    OPENSSL_free(e);
}

/*
 * Callback for lh_DGRAM_CONN_ENTRY_doall to free all entries.
 */
static void conn_entry_free_cb(DGRAM_CONN_ENTRY *e)
{
    conn_entry_free(e);
}

/*
 * Lookup a connection by peer address from URXE.
 */
static SSL *addr_lookup(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e)
{
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;
    DGRAM_CONN_ENTRY key;
    DGRAM_CONN_ENTRY *result;

    if (lookup == NULL || lookup->impl_data == NULL || e == NULL)
        return NULL;

    htable = (LHASH_OF(DGRAM_CONN_ENTRY) *)lookup->impl_data;

    memset(&key, 0, sizeof(key));
    BIO_ADDR_copy(&key.peer, &e->peer);

    /* Build hashkey for the lookup key */
    key.hashkey = build_hashkey(&e->peer, &key.hashkey_len);
    if (key.hashkey == NULL)
        return NULL;

    result = lh_DGRAM_CONN_ENTRY_retrieve(htable, &key);

    OPENSSL_free(key.hashkey);

    if (result == NULL)
        return NULL;

    return result->ssl;
}

/*
 * Register a connection with peer address from URXE.
 */
static int addr_register_conn(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e,
    SSL *ssl)
{
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;
    DGRAM_CONN_ENTRY *entry, *old;

    if (lookup == NULL || lookup->impl_data == NULL || e == NULL || ssl == NULL)
        return 0;

    htable = (LHASH_OF(DGRAM_CONN_ENTRY) *)lookup->impl_data;

    entry = OPENSSL_zalloc(sizeof(*entry));
    if (entry == NULL)
        return 0;

    BIO_ADDR_copy(&entry->peer, &e->peer);
    entry->ssl = ssl;
    entry->hashkey = build_hashkey(&e->peer, &entry->hashkey_len);
    if (entry->hashkey == NULL) {
        OPENSSL_free(entry);
        return 0;
    }

    old = lh_DGRAM_CONN_ENTRY_insert(htable, entry);

    /* Check if insert failed due to allocation error */
    if (lh_DGRAM_CONN_ENTRY_error(htable)) {
        conn_entry_free(entry);
        /* Don't free old since it is still in the hash table since insert failed */
        return 0;
    }

    /* Free any old entry that was replaced (duplicate key) */
    conn_entry_free(old);

    return 1;
}

/*
 * Register a connection by peer address from BIO_ADDR directly.
 * This is used when we don't have a URXE available.
 */
static int addr_register_conn_addr(DGRAM_CONN_LOOKUP *lookup, const BIO_ADDR *peer,
    SSL *ssl)
{
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;
    DGRAM_CONN_ENTRY *entry, *old;

    if (lookup == NULL || lookup->impl_data == NULL || peer == NULL || ssl == NULL)
        return 0;

    htable = (LHASH_OF(DGRAM_CONN_ENTRY) *)lookup->impl_data;

    entry = OPENSSL_zalloc(sizeof(*entry));
    if (entry == NULL)
        return 0;

    BIO_ADDR_copy(&entry->peer, peer);
    entry->ssl = ssl;
    entry->hashkey = build_hashkey(peer, &entry->hashkey_len);
    if (entry->hashkey == NULL) {
        OPENSSL_free(entry);
        return 0;
    }

    old = lh_DGRAM_CONN_ENTRY_insert(htable, entry);

    /* Check if insert failed due to allocation error */
    if (lh_DGRAM_CONN_ENTRY_error(htable)) {
        conn_entry_free(entry);
        /* Don't free old since it is still in the hash table since insert failed */
        return 0;
    }

    /* Free any old entry that was replaced (duplicate key) */
    conn_entry_free(old);

    return 1;
}

/*
 * Unregister a connection by peer address.
 */
static int addr_unregister_conn(DGRAM_CONN_LOOKUP *lookup, const BIO_ADDR *peer)
{
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;
    DGRAM_CONN_ENTRY lookup_key;
    DGRAM_CONN_ENTRY *removed;

    if (lookup == NULL || lookup->impl_data == NULL || peer == NULL)
        return 0;

    htable = (LHASH_OF(DGRAM_CONN_ENTRY) *)lookup->impl_data;

    memset(&lookup_key, 0, sizeof(lookup_key));
    BIO_ADDR_copy(&lookup_key.peer, peer);

    lookup_key.hashkey = build_hashkey(peer, &lookup_key.hashkey_len);
    if (lookup_key.hashkey == NULL)
        return 0;

    removed = lh_DGRAM_CONN_ENTRY_delete(htable, &lookup_key);

    OPENSSL_free(lookup_key.hashkey);

    if (removed != NULL) {
        conn_entry_free(removed);
        return 1;
    }

    return 0;
}

/*
 * Free the lookup structure and all entries.
 */
static void addr_free(DGRAM_CONN_LOOKUP *lookup)
{
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;

    if (lookup == NULL)
        return;

    if (lookup->impl_data != NULL) {
        htable = (LHASH_OF(DGRAM_CONN_ENTRY) *)lookup->impl_data;
        lh_DGRAM_CONN_ENTRY_doall(htable, conn_entry_free_cb);
        lh_DGRAM_CONN_ENTRY_free(htable);
    }

    OPENSSL_free(lookup);
}

/*
 * Context structure for iteration callback.
 */
typedef struct {
    ossl_dgram_conn_lookup_iter_fn user_cb;
    void *user_arg;
} ADDR_FOREACH_CTX;

/*
 * Internal callback for lh_doall_arg that invokes the user's callback.
 */
static void addr_foreach_cb(DGRAM_CONN_ENTRY *e, void *arg)
{
    ADDR_FOREACH_CTX *ctx = arg;

    if (ctx->user_cb != NULL)
        ctx->user_cb(e->ssl, &e->peer, ctx->user_arg);
}

IMPLEMENT_LHASH_DOALL_ARG(DGRAM_CONN_ENTRY, void);

/*
 * Iterate over all connections, calling the callback for each.
 */
static void addr_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb, void *arg)
{
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;
    ADDR_FOREACH_CTX ctx;

    if (lookup == NULL || lookup->impl_data == NULL || cb == NULL)
        return;

    htable = (LHASH_OF(DGRAM_CONN_ENTRY) *)lookup->impl_data;
    ctx.user_cb = cb;
    ctx.user_arg = arg;

    lh_DGRAM_CONN_ENTRY_doall_void(htable, addr_foreach_cb, &ctx);
}

static const DGRAM_CONN_LOOKUP_METHODS addr_methods = {
    addr_lookup,
    addr_register_conn,
    addr_register_conn_addr,
    addr_unregister_conn,
    addr_foreach,
    addr_free
};

/*
 * Create a new address-based connection lookup for DTLS.
 */
DGRAM_CONN_LOOKUP *ossl_dgram_conn_lookup_new_addr(void)
{
    DGRAM_CONN_LOOKUP *lookup;
    LHASH_OF(DGRAM_CONN_ENTRY) *htable;

    lookup = OPENSSL_zalloc(sizeof(*lookup));
    if (lookup == NULL)
        return NULL;

    htable = lh_DGRAM_CONN_ENTRY_new(conn_entry_hash, conn_entry_cmp);
    if (htable == NULL) {
        OPENSSL_free(lookup);
        return NULL;
    }

    lookup->methods = &addr_methods;
    lookup->impl_data = htable;

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

int ossl_dgram_conn_lookup_register(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_URXE *e, SSL *ssl)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->register_conn == NULL)
        return 0;
    return lookup->methods->register_conn(lookup, e, ssl);
}

int ossl_dgram_conn_lookup_register_addr(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer, SSL *ssl)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->register_conn_addr == NULL)
        return 0;
    return lookup->methods->register_conn_addr(lookup, peer, ssl);
}

int ossl_dgram_conn_lookup_unregister(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->unregister_conn == NULL)
        return 0;
    return lookup->methods->unregister_conn(lookup, peer);
}

void ossl_dgram_conn_lookup_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb, void *arg)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->foreach == NULL)
        return;
    lookup->methods->foreach (lookup, cb, arg);
}

void ossl_dgram_conn_lookup_free(DGRAM_CONN_LOOKUP *lookup)
{
    if (lookup == NULL || lookup->methods == NULL
        || lookup->methods->free == NULL)
        return;
    lookup->methods->free(lookup);
}

#endif /* OPENSSL_NO_DTLS */
