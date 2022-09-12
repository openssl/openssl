/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_route.h"
#include "internal/list.h"
#include <openssl/rand.h>
#include "quic_local.h"

struct quic_route_st {
    OSSL_LIST_MEMBER(remote_ids, QUIC_ROUTE);
    QUIC_ROUTE_TABLE *tbl;
    QUIC_CONN_ID local;
    QUIC_CONN_ID remote;
    uint64_t     seq_no;        /* Sequence number for both ends */
};

DEFINE_LHASH_OF_EX(QUIC_ROUTE);

/*
 * A list of remote IDs.  These are stored in ascending order in the list because
 * the only supported operations are retire a batch of low numbered IDs or add
 * new high numbered IDs.  The required update operations being append and
 * pop from front and some inspection.
 *
 * This could be to single linked list once such is implemented.
 */
DEFINE_LIST_OF(remote_ids, QUIC_ROUTE);

struct quic_route_table {
    SSL_CTX *sslctx;
    LHASH_OF(QUIC_ROUTE) *remote_id_tbl;
    OSSL_LIST(remote_ids) remote_id_list;
    uint64_t unretired;         /* Highest non-retired connection ID */
};

/****************************************************************************
 * Connection ID handling                                                   *
 ****************************************************************************/

/*
 * Generate a new local connection ID
 */
int ossl_quic_conn_id_generate(OSSL_LIB_CTX *ctx, QUIC_CONN_ID *cid)
{
    cid->id_len = QUIC_CONN_ID_LEN;
    return RAND_bytes_ex(ctx, cid->id, cid->id_len, cid->id_len * 8) > 0;
}

int ossl_quic_conn_id_set(QUIC_CONN_ID *cid, const unsigned char *id,
                          unsigned int id_len)
{
    if (id_len > sizeof(cid->id))
        return 0;
#ifndef NDEBUG
    if (id_len < sizeof(cid->id))
        memset(cid->id + id_len, 0, sizeof(cid->id) - id_len);
#endif
    memcpy(cid->id, id, cid->id_len = id_len);
    return 1;
}

/****************************************************************************
 * Hash table lookup functions                                              *
 ****************************************************************************/

static unsigned long id_hash(const QUIC_CONN_ID *id)
{
    /*
     * Naive implemenation of Bernstein's DJBX33A hash, starting with the length
     * byte, followed by the ID itself.  For local ID's we could do better because
     * we know the fixed length but it's unlikely to be worthwhile.
     */
    const unsigned int len = id->id_len;
    unsigned long h = len;
    unsigned int i;

    for (i = 0; i < len; i++)
        h = 33 * h + id->id[i];
    return h;
}

static int id_cmp(const QUIC_CONN_ID *a, const QUIC_CONN_ID *b)
{
    if (a->id_len != b->id_len)
        return a->id_len > b->id_len ? 1 : -1;
    return memcmp(a->id, b->id, a->id_len);
}

static unsigned long local_id_hash(const QUIC_ROUTE *a)
{
    return id_hash(&a->local);
}

static int local_id_cmp(const QUIC_ROUTE *a, const QUIC_ROUTE *b)
{
    return id_cmp(&a->local, &b->local);
}

static unsigned long remote_id_hash(const QUIC_ROUTE *a)
{
    return id_hash(&a->remote);
}

static int remote_id_cmp(const QUIC_ROUTE *a, const QUIC_ROUTE *b)
{
    return id_cmp(&a->remote, &b->remote);
}

/****************************************************************************
 * Connection ID cache routines                                             *
 ****************************************************************************/

QUIC_ROUTE_TABLE *ossl_quic_route_table_new(SSL_CTX *sslctx)
{
    QUIC_ROUTE_TABLE *r;

    r = OPENSSL_malloc(sizeof(*r));
    if (r == NULL)
        goto err;

    r->remote_id_tbl = lh_QUIC_ROUTE_new(&remote_id_hash, &remote_id_cmp);
    if (r == NULL)
        goto err;

    if (sslctx->quic_route_table == NULL) {
        sslctx->quic_route_table = lh_QUIC_ROUTE_new(&local_id_hash, &local_id_cmp);
        if (sslctx->quic_route_table == NULL)
            goto err;
    }

    ossl_list_remote_ids_init(&r->remote_id_list);
    r->sslctx = sslctx;
    r->unretired = 0;
    return r;

 err:
    OPENSSL_free(r);
    lh_QUIC_ROUTE_free(sslctx->quic_route_table);
    sslctx->quic_route_table = NULL;
    return NULL;
}

void ossl_quic_route_table_free(QUIC_ROUTE_TABLE *routes)
{
    QUIC_ROUTE *p, *pnext;

    if (routes != NULL) {
        lh_QUIC_ROUTE_free(routes->remote_id_tbl);
        for (p = ossl_list_remote_ids_head(&routes->remote_id_list);
             p != NULL; p = pnext) {
            pnext = ossl_list_remote_ids_next(p);
            OPENSSL_free(p);
        }
        OPENSSL_free(routes);
    }
}

QUIC_ROUTE *ossl_route_table_get0_route_from_local(
        const QUIC_ROUTE_TABLE *cache,
        const unsigned char *conn_id, size_t conn_id_len)
{
    QUIC_ROUTE conn;

    if (!ossl_quic_conn_id_set(&conn.local, conn_id, conn_id_len))
        return NULL;
    return lh_QUIC_ROUTE_retrieve(cache->sslctx->quic_route_table, &conn);
}

QUIC_ROUTE *ossl_route_table_get0_route_from_remote(
        const QUIC_ROUTE_TABLE *cache,
        const unsigned char *conn_id, size_t conn_id_len)
{
    QUIC_ROUTE *r, conn;

    if (!ossl_quic_conn_id_set(&conn.remote, conn_id, conn_id_len))
        return NULL;
    r = lh_QUIC_ROUTE_retrieve(cache->remote_id_tbl, &conn);
    return r;
}

QUIC_ROUTE *ossl_quic_route_new(QUIC_ROUTE_TABLE *routes,
                                const unsigned char *remote_id, size_t remote_id_len)
{
    QUIC_ROUTE *r = OPENSSL_zalloc(sizeof(*r));
    QUIC_ROUTE *p;

    if (r != NULL) {
        r->tbl = routes;
        ossl_quic_conn_id_generate(routes->sslctx->libctx, &r->local);

        p = ossl_list_remote_ids_head(&routes->remote_id_list);
        r->seq_no = p != NULL ? p->seq_no + 1 : 0;

        if (lh_QUIC_ROUTE_insert(routes->sslctx->quic_route_table, r) != NULL
                || lh_QUIC_ROUTE_error(routes->sslctx->quic_route_table) > 0)
            goto err;
        if (remote_id != NULL
                && !ossl_quic_route_set_remote_connection_id(r, remote_id,
                                                             remote_id_len)) {
            lh_QUIC_ROUTE_delete(routes->sslctx->quic_route_table, r);
            goto err;
        }
        ossl_list_remote_ids_init_elem(r);
        ossl_list_remote_ids_insert_head(&routes->remote_id_list, r);
    }
    return r;

 err:
    OPENSSL_free(r);
    return NULL;
}

/*
 * Retire by sequence number up to and including the one specified.
 */
int ossl_quic_route_retire(QUIC_ROUTE_TABLE *routes, uint64_t seq_no)
{
    seq_no++;
    routes->unretired = routes->unretired > seq_no ? routes->unretired : seq_no;
    return 1;
}

/*
 * Delete by sequence number up to and including the one specified.
 */
int ossl_quic_route_remove(QUIC_ROUTE_TABLE *routes, uint64_t seq_no)
{
    QUIC_ROUTE *p, *pprev;

    ossl_quic_route_retire(routes, seq_no + 1);
    for (p = ossl_list_remote_ids_tail(&routes->remote_id_list);
         p != NULL && p->seq_no <= seq_no;
         p = pprev) {
        pprev = ossl_list_remote_ids_prev(p);
        ossl_list_remote_ids_remove(&routes->remote_id_list, p);
        lh_QUIC_ROUTE_delete(routes->remote_id_tbl, p);
        lh_QUIC_ROUTE_delete(routes->sslctx->quic_route_table, p);
        OPENSSL_free(p);
    }
    return 1;
}

/****************************************************************************
 * Connection ID and route routines                                         *
 ****************************************************************************/

uint64_t ossl_quic_route_get_sequence_number(const QUIC_ROUTE *route)
{
    return route->seq_no;
}

int ossl_quic_route_is_retired(const QUIC_ROUTE *route)
{
    return route->seq_no < route->tbl->unretired;
}

const QUIC_CONN_ID *ossl_quic_route_get_local_connection_id(const QUIC_ROUTE *route)
{
    return &route->local;
}

const QUIC_CONN_ID *ossl_quic_route_get_remote_connection_id(const QUIC_ROUTE *route)
{
    return &route->remote;
}

QUIC_ROUTE_TABLE *ossl_quic_route_get_route_table(const QUIC_ROUTE *route)
{
    return route->tbl;
}

int ossl_quic_route_set_remote_connection_id(QUIC_ROUTE *route,
                                             const unsigned char *remote_id,
                                             size_t remote_id_len)
{
    if (route->remote.id_len == 0
            && ossl_quic_conn_id_set(&route->remote, remote_id, remote_id_len)
            && (lh_QUIC_ROUTE_insert(route->tbl->remote_id_tbl, route) != NULL
                || lh_QUIC_ROUTE_error(route->tbl->remote_id_tbl) == 0))
        return 1;
    return 0;
}
