/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "../ssl_locl.h"
#include "statem_locl.h"

/*
 * Comparison function used in a call to qsort (see tls_collect_extensions()
 * below.)
 * The two arguments |p1| and |p2| are expected to be pointers to RAW_EXTENSIONs
 *
 * Returns:
 *  1 if the type for p1 is greater than p2
 *  0 if the type for p1 and p2 are the same
 * -1 if the type for p1 is less than p2
 */
static int compare_extensions(const void *p1, const void *p2)
{
    const RAW_EXTENSION *e1 = (const RAW_EXTENSION *)p1;
    const RAW_EXTENSION *e2 = (const RAW_EXTENSION *)p2;

    if (e1->type < e2->type)
        return -1;
    else if (e1->type > e2->type)
        return 1;

    return 0;
}

/*
 * Gather a list of all the extensions. We don't actually process the content
 * of the extensions yet, except to check their types.
 *
 * Per http://tools.ietf.org/html/rfc5246#section-7.4.1.4, there may not be
 * more than one extension of the same type in a ClientHello or ServerHello.
 * This function returns 1 if all extensions are unique and we have parsed their
 * types, and 0 if the extensions contain duplicates, could not be successfully
 * parsed, or an internal error occurred.
 */
/*
 * TODO(TLS1.3): Refactor ServerHello extension parsing to use this and then
 * remove tls1_check_duplicate_extensions()
 */
int tls_collect_extensions(PACKET *packet, RAW_EXTENSION **res,
                             size_t *numfound, int *ad)
{
    PACKET extensions = *packet;
    size_t num_extensions = 0, i = 0;
    RAW_EXTENSION *raw_extensions = NULL;

    /* First pass: count the extensions. */
    while (PACKET_remaining(&extensions) > 0) {
        unsigned int type;
        PACKET extension;

        if (!PACKET_get_net_2(&extensions, &type) ||
            !PACKET_get_length_prefixed_2(&extensions, &extension)) {
            *ad = SSL_AD_DECODE_ERROR;
            goto err;
        }
        num_extensions++;
    }

    if (num_extensions > 0) {
        raw_extensions = OPENSSL_malloc(sizeof(*raw_extensions)
                                        * num_extensions);
        if (raw_extensions == NULL) {
            *ad = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Second pass: collect the extensions. */
        for (i = 0; i < num_extensions; i++) {
            if (!PACKET_get_net_2(packet, &raw_extensions[i].type) ||
                !PACKET_get_length_prefixed_2(packet,
                                              &raw_extensions[i].data)) {
                /* This should not happen. */
                *ad = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        if (PACKET_remaining(packet) != 0) {
            *ad = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_LENGTH_MISMATCH);
            goto err;
        }
        /* Sort the extensions and make sure there are no duplicates. */
        qsort(raw_extensions, num_extensions, sizeof(*raw_extensions),
              compare_extensions);
        for (i = 1; i < num_extensions; i++) {
            if (raw_extensions[i - 1].type == raw_extensions[i].type) {
                *ad = SSL_AD_DECODE_ERROR;
                goto err;
            }
        }
    }

    *res = raw_extensions;
    *numfound = num_extensions;
    return 1;

 err:
    OPENSSL_free(raw_extensions);
    return 0;
}
