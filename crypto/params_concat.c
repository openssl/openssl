/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/params.h"
#include "internal/packet.h"

static int setbuf_fromparams(size_t n, OSSL_PARAM *p[],
    unsigned char *out, size_t *outlen)
{
    int ret = 0;
    WPACKET pkt;
    size_t i;

    if (out == NULL) {
        if (!WPACKET_init_null(&pkt, 0))
            return 0;
    } else {
        if (!WPACKET_init_static_len(&pkt, out, *outlen, 0))
            return 0;
    }

    for (i = 0; i < n; i++) {
        if (p[i]->data_type != OSSL_PARAM_OCTET_STRING)
            goto err;
        if (p[i]->data != NULL
            && p[i]->data_size != 0
            && !WPACKET_memcpy(&pkt, p[i]->data, p[i]->data_size))
            goto err;
    }
    if (!WPACKET_get_total_written(&pkt, outlen)
        || !WPACKET_finish(&pkt))
        goto err;
    ret = 1;
err:
    WPACKET_cleanup(&pkt);
    return ret;
}

int ossl_param_get1_concat_octet_string(size_t n, OSSL_PARAM *params[],
    unsigned char **out, size_t *out_len)
{
    unsigned char *res;
    size_t sz = 0;

    if (n == 0)
        return 1;

    /* Calculate the total size */
    if (!setbuf_fromparams(n, params, NULL, &sz))
        return 0;

    /* Special case zero length */
    if (sz == 0) {
        if ((res = OPENSSL_zalloc(1)) == NULL)
            return 0;
        goto fin;
    }

    /* Allocate the buffer */
    res = OPENSSL_malloc(sz);
    if (res == NULL)
        return 0;

    /* Concat one or more OSSL_KDF_PARAM_INFO fields */
    if (!setbuf_fromparams(n, params, res, &sz)) {
        OPENSSL_clear_free(res, sz);
        return 0;
    }

fin:
    OPENSSL_clear_free(*out, *out_len);
    *out = res;
    *out_len = sz;
    return 1;
}
