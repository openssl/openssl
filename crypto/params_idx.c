/*
 *
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/e_os.h"
#include "internal/param_names.h"
#include <string.h>

struct ossl_param_lookup {
    int name;
    int idx;
};

/* Need to forward declare this even though it is entirely intenal */
const struct ossl_param_lookup *
ossl_param_lookup_internal (register const char *str, register size_t len);

int ossl_scan_params_for_idx(const OSSL_PARAM *params, OSSL_PARAM_IDX *idx)
{
    int c = 0;
    unsigned char i;
    const struct ossl_param_lookup *p;

    memset(idx, 0xff, sizeof(*idx));
    for (i = 0; params[i].key != NULL; i++) {
        p = ossl_param_lookup_internal(params[i].key, strlen(params[i].key));
        if (p->idx >= 0) {
            c++;
            if (idx->p[p->idx] == 0xff)
                idx->p[p->idx] = i;
        }
    }
    return c;
}

/* Include the machine generated hash lookup */
#include "params_table.inc"

