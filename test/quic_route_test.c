/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"
#include "internal/quic_route.h"
#include "../ssl/ssl_local.h"

DEFINE_LHASH_OF_EX(QUIC_ROUTE);

static int quic_route_test(void)
{
    SSL_CTX *sslctx = NULL;
    QUIC_ROUTE_TABLE *rt = NULL;
    QUIC_ROUTE *r;
    const QUIC_CONN_ID *c;
    static const unsigned char rname_0[] = { 'A', 'B', 'C' };
    static const unsigned char rname_1[] = { '1', '2', '3', '4' };
    static const unsigned char rname_2[] = { 'x', 'y', 'z' };
    static const unsigned char rname_e[] = { '.', '.', '.' };
#define RT(n)   rname_ ## n, sizeof(rname_ ## n)
    int ret = 0;

    if (!TEST_ptr(sslctx = SSL_CTX_new(OSSL_QUIC_client_method()))
            || !TEST_ptr(rt = ossl_quic_route_table_new(sslctx)))
        goto err;

    /* Add some routes */
    if (!TEST_ptr(r = ossl_quic_route_new(rt, RT(0)))
            || !TEST_ptr(r = ossl_quic_route_new(rt, NULL, 0))
            || !TEST_true(ossl_quic_route_set_remote_connection_id(r, RT(1)))
            || !TEST_false(ossl_quic_route_set_remote_connection_id(r, RT(e)))
            || !TEST_ptr(r = ossl_quic_route_new(rt, RT(2)))) {
        OPENSSL_free(r);
        goto err;
    }

    /* Check contents */
    if (!TEST_ptr(r = ossl_route_table_get0_route_from_remote(rt, RT(0)))
            || !TEST_uint64_t_eq(ossl_quic_route_get_sequence_number(r), 0)
            || !TEST_false(ossl_quic_route_is_retired(r))
            || !TEST_ptr(c = ossl_quic_route_get_local_connection_id(r))
            || !TEST_ptr_eq(r, ossl_route_table_get0_route_from_local(rt, c->id,
                                                                      c->id_len))
            || !TEST_ptr_eq(rt, ossl_quic_route_get_route_table(r))

            || !TEST_ptr(r = ossl_route_table_get0_route_from_remote(rt, RT(1)))
            || !TEST_uint64_t_eq(ossl_quic_route_get_sequence_number(r), 1)
            || !TEST_false(ossl_quic_route_is_retired(r))
            || !TEST_ptr(c = ossl_quic_route_get_local_connection_id(r))
            || !TEST_ptr_eq(r, ossl_route_table_get0_route_from_local(rt, c->id,
                                                                      c->id_len))
            || !TEST_ptr_eq(rt, ossl_quic_route_get_route_table(r))

            || !TEST_ptr(r = ossl_route_table_get0_route_from_remote(rt, RT(2)))
            || !TEST_uint64_t_eq(ossl_quic_route_get_sequence_number(r), 2)
            || !TEST_false(ossl_quic_route_is_retired(r))
            || !TEST_ptr(c = ossl_quic_route_get_local_connection_id(r))
            || !TEST_ptr_eq(r, ossl_route_table_get0_route_from_local(rt, c->id,
                                                                      c->id_len))
            || !TEST_ptr_eq(rt, ossl_quic_route_get_route_table(r))

            || !TEST_ptr_null(ossl_route_table_get0_route_from_remote(rt, RT(e))))
        goto err;

    /* Retire and remove some */
    if (!TEST_true(ossl_quic_route_retire(rt, 1))
            || !TEST_true(ossl_quic_route_remove(rt, 0)))
        goto err;

    /* Check sanity of what's left */
    if (!TEST_ptr_null(ossl_route_table_get0_route_from_remote(rt, RT(0)))
            || !TEST_ptr(r = ossl_route_table_get0_route_from_remote(rt, RT(1)))
            || !TEST_uint64_t_eq(ossl_quic_route_get_sequence_number(r), 1)
            || !TEST_true(ossl_quic_route_is_retired(r))
            || !TEST_ptr(c = ossl_quic_route_get_local_connection_id(r))
            || !TEST_ptr_eq(r, ossl_route_table_get0_route_from_local(rt, c->id,
                                                                      c->id_len))
            || !TEST_ptr_eq(rt, ossl_quic_route_get_route_table(r))

            || !TEST_ptr(r = ossl_route_table_get0_route_from_remote(rt, RT(2)))
            || !TEST_uint64_t_eq(ossl_quic_route_get_sequence_number(r), 2)
            || !TEST_false(ossl_quic_route_is_retired(r))
            || !TEST_ptr(c = ossl_quic_route_get_local_connection_id(r))
            || !TEST_ptr_eq(r, ossl_route_table_get0_route_from_local(rt, c->id,
                                                                      c->id_len))
            || !TEST_ptr_eq(rt, ossl_quic_route_get_route_table(r))

            || !TEST_ptr_null(ossl_route_table_get0_route_from_remote(rt, RT(e))))
        goto err;

    ret = 1;
 err:
    SSL_CTX_free(sslctx);
    ossl_quic_route_table_free(rt);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(quic_route_test);
    return 1;
}
