/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include "../ssl_local.h"
#include <openssl/trace.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "record_local.h"
#include "internal/cryptlib.h"

void SSL3_RECORD_release(SSL3_RECORD *r, size_t num_recs)
{
    size_t i;

    for (i = 0; i < num_recs; i++) {
        OPENSSL_free(r[i].comp);
        r[i].comp = NULL;
    }
}

void SSL3_RECORD_set_seq_num(SSL3_RECORD *r, const unsigned char *seq_num)
{
    memcpy(r->seq_num, seq_num, SEQ_NUM_SIZE);
}

uint32_t ossl_get_max_early_data(SSL_CONNECTION *s)
{
    uint32_t max_early_data;
    SSL_SESSION *sess = s->session;

    /*
     * If we are a client then we always use the max_early_data from the
     * session/psksession. Otherwise we go with the lowest out of the max early
     * data set in the session and the configured max_early_data.
     */
    if (!s->server && sess->ext.max_early_data == 0) {
        if (!ossl_assert(s->psksession != NULL
                         && s->psksession->ext.max_early_data > 0)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        sess = s->psksession;
    }

    if (!s->server)
        max_early_data = sess->ext.max_early_data;
    else if (s->ext.early_data != SSL_EARLY_DATA_ACCEPTED)
        max_early_data = s->recv_max_early_data;
    else
        max_early_data = s->recv_max_early_data < sess->ext.max_early_data
                         ? s->recv_max_early_data : sess->ext.max_early_data;

    return max_early_data;
}

int ossl_early_data_count_ok(SSL_CONNECTION *s, size_t length, size_t overhead,
                             int send)
{
    uint32_t max_early_data;

    max_early_data = ossl_get_max_early_data(s);

    if (max_early_data == 0) {
        SSLfatal(s, send ? SSL_AD_INTERNAL_ERROR : SSL_AD_UNEXPECTED_MESSAGE,
                 SSL_R_TOO_MUCH_EARLY_DATA);
        return 0;
    }

    /* If we are dealing with ciphertext we need to allow for the overhead */
    max_early_data += overhead;

    if (s->early_data_count + length > max_early_data) {
        SSLfatal(s, send ? SSL_AD_INTERNAL_ERROR : SSL_AD_UNEXPECTED_MESSAGE,
                 SSL_R_TOO_MUCH_EARLY_DATA);
        return 0;
    }
    s->early_data_count += length;

    return 1;
}
