/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_ROUTE_H
# define OSSL_QUIC_ROUTE_H

# include "internal/quic_types.h"

/*
 * Generate a new local connection ID
 */
int ossl_quic_conn_id_generate(OSSL_LIB_CTX *ctx, QUIC_CONN_ID *cid);

/*
 * Set a connection ID to the specified ID
 */
int ossl_quic_conn_id_set(QUIC_CONN_ID *cid, const unsigned char *id,
                          unsigned int id_len);

QUIC_ROUTE_TABLE *ossl_quic_route_table_new(SSL_CTX *sslctx);
void ossl_quic_route_table_free(QUIC_ROUTE_TABLE *routes);

QUIC_ROUTE *ossl_quic_route_new(QUIC_ROUTE_TABLE *routes,
                                const unsigned char *remote_id,
                                size_t remote_id_len);

/*
 * Query functions base on local or remote IDs
 */
QUIC_ROUTE *ossl_route_table_get0_route_from_local(
        ossl_unused const QUIC_ROUTE_TABLE *cache,
        const unsigned char *conn_id, size_t conn_id_len);
QUIC_ROUTE *ossl_route_table_get0_route_from_remote(
        const QUIC_ROUTE_TABLE *cache,
        const unsigned char *conn_id, size_t conn_id_len);

/*
 * Retire/remove by sequence number up to and including the one specified.
 */
int ossl_quic_route_retire(QUIC_ROUTE_TABLE *routes, uint64_t seq_no);
int ossl_quic_route_remove(QUIC_ROUTE_TABLE *routes, uint64_t seq_no);

uint64_t ossl_quic_route_get_sequence_number(const QUIC_ROUTE *route);
int ossl_quic_route_is_retired(const QUIC_ROUTE *route);
const QUIC_CONN_ID *
        ossl_quic_route_get_local_connection_id(const QUIC_ROUTE *route);
const QUIC_CONN_ID *
        ossl_quic_route_get_remote_connection_id(const QUIC_ROUTE *route);
int ossl_quic_route_set_remote_connection_id(QUIC_ROUTE *route,
                                             const unsigned char *remote_id,
                                             size_t remote_id_len);
QUIC_ROUTE_TABLE *ossl_quic_route_get_route_table(const QUIC_ROUTE *route);

/*
 * Clean up on exit
 */
void ossl_quic_local_connection_id_free(void);

#endif
