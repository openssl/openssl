/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/param_check.h>
#include "param_type_data.h"         /* Generated file */

/*
 * OSSL_PARAM_checks reuses OSSL_PARAM for parameter type definitions, and
 * expect the following:
 *
 * key          parameter name
 * data_type    type
 * data         is NULL
 * data_size    is 0 for arbitrary size, otherwise the maximum size in bytes
 * return_size  is NULL
 */

/* tbc = to be checked */
int OSSL_PARAM_check_one(const OSSL_PARAM *tbc,
                         const OSSL_PARAM *defs, int intent,
                         int (*report_cb)(void *, const char fmt, ...),
                         void *report_cb_data)
{
    int ok = 1;
    const OSSL_PARAM *p;

    if (intent != 0              /* setting params */
        && intent != 1) {        /* getting params */
        report_cb(report_cb_data,
                  "Error: intent (%d) must be 0 (params to set) or 1 (params to get)\n",
                  intent);
        return 0;
    }

    if (tbc->key == NULL) {
        report_cb(report_cb_data,
                  "Error: Element %zu has key == NULL\n", i);
        ok = 0;
    } else if ((p = OSSL_PARAM_locate(defs, tbc[i].key)) != NULL) {
        int tbc_type = tbc[i].data_type;
        int def_type = p->data_type;

        /*
         * we match C integer coersion, so make signed and unsigned
         * integers equivalent for the simpler type checks.
         */
        if (tbc_type == OSSL_PARAM_INTEGER)
            tbc_type = OSSL_PARAM_UNSIGNED_INTEGER;
        if (def_type == OSSL_PARAM_INTEGER)
            def_type = OSSL_PARAM_UNSIGNED_INTEGER;

        if (tbc_type != def_type) {
            report_cb(report_cb_data,
                      "Error: parameter type (%d) doesn't match the parameter definition type (%d)\n",
                      tbc[i].data_type,
                      p->data_type);
            ok = 0;
        } else if (intent == 0 &&
                   p->data_size != 0 && tbc->data_size > p->data_size) {
            report_cb("Error: trying to set parameter \"%s\" with too much data (%zu > %zu)\n",
                      tbc->key, tbc->data_size, p->data_size);
            ok = 0;
        } else if (intent == 1 &&
                   p->data_size != 0 && tbc->data_size < p->data_size) {
            report_cb("Error: trying to get parameter \"%s\" with a too small data space (%zu < %zu)\n",
                      tbc->key, tbc->data_size, p->data_size);
            ok = 0;
        }
    }

    return ok;
}

int OSSL_PARAM_check_all(const OSSL_PARAM *tbc, size_t tbc_elems,
                         const OSSL_PARAM *defs, int intent,
                         int (*report_cb)(void *, const char fmt, ...),
                         void *report_cb_data)
{
    int ok = 1;
    size_t i;
    size_t tbc_last = tbc_elems - 1;
    int count[100];              /* Count of times each definition occurs */

    if (intent != 0              /* setting params */
        && intent != 1) {        /* getting params */
        report_cb(report_cb_data,
                  "Error: intent (%d) must be 0 (params to set) or 1 (params to get)\n",
                  intent);
        return 0;
    }

    memset(count, 0, sizeof(count));
    if (tbc[tbc_last].key != NULL) {
        report_cb(report_cb_data,
                  "Error: Improper termination; last element has key = \"%s\"\n",
                  tbc[tbc_last].key);
        ok = 0;
    }

    for (i = 0; i < tbc_elems; i++) {
        if (i < tbc_last || tbc[i].key != NULL) {
            if (!OSSL_PARAM_check_one(&tbc[i], defs, intent,
                                      report_cb, report_cb_data))
                ok = 0;
        }
    }

    return ok;
}
