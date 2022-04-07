/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include "recordmethod.h"

struct ossl_record_layer_st
{
    /* Placeholder until we have real data to store */
    int dummy;
};

static OSSL_RECORD_LAYER *tls_new_record_layer(int vers, int role, int direction,
                                               int level, unsigned char *secret,
                                               size_t secretlen, SSL_CIPHER *c,
                                               BIO *transport, BIO_ADDR *local,
                                               BIO_ADDR *peer,
                                               OSSL_PARAM *settings,
                                               OSSL_PARAM *options)
{
    OSSL_RECORD_LAYER *rl = OPENSSL_zalloc(sizeof(*rl));

    return rl;
}

static void tls_free(OSSL_RECORD_LAYER *rl)
{
    OPENSSL_free(rl);
}

static int tls_reset(OSSL_RECORD_LAYER *rl)
{
    memset(rl, 0, sizeof(*rl));
    return 1;
}

static int tls_unprocessed_read_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_processed_read_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_app_data_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_write_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_get_max_record_len(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_get_max_records(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_write_records(OSSL_RECORD_LAYER *rl,
                             OSSL_RECORD_TEMPLATE **templates, size_t numtempl,
                             size_t allowance, size_t *sent)
{
    return 0;
}

static int tls_retry_write_records(OSSL_RECORD_LAYER *rl, size_t allowance,
                                   size_t *sent)
{
    return 0;
}

static int tls_read_record(OSSL_RECORD_LAYER *rl, void **rechandle,
                           int *rversion, int *type, unsigned char **data,
                           size_t *datalen, uint16_t *epoch,
                           unsigned char *seq_num)
{
    return 0;
}

static void tls_release_record(OSSL_RECORD_LAYER *rl, void *rechandle)
{
    return;
}

const OSSL_RECORD_METHOD ossl_tls_record_method = {
    tls_new_record_layer,
    tls_free,
    tls_reset,
    tls_unprocessed_read_pending,
    tls_processed_read_pending,
    tls_app_data_pending,
    tls_write_pending,
    tls_get_max_record_len,
    tls_get_max_records,
    tls_write_records,
    tls_retry_write_records,
    tls_read_record,
    tls_release_record
};
