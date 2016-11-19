/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/lhash.h>
#include "store_local.h"

static unsigned long scheme_loader_hash(const SCHEME_LOADER *v)
{
    return OPENSSL_LH_strhash(v->scheme);
}

static int scheme_loader_cmp(const SCHEME_LOADER *a,
                               const SCHEME_LOADER *b)
{
    if (a->scheme != NULL && b->scheme != NULL) {
        return strcmp(a->scheme, b->scheme);
    } else if (a->scheme == b->scheme)
        return 0;
    else
        return a->scheme == NULL ? -1 : 1;
}

static void scheme_loader_cleanup(SCHEME_LOADER *scheme_loader)
{
    if (!scheme_loader->no_free) {
        OPENSSL_free(scheme_loader->scheme);
        OPENSSL_free(scheme_loader);
    }
}

DEFINE_LHASH_OF(SCHEME_LOADER) *scheme_register = NULL;

int register_loader_int(SCHEME_LOADER *scheme_loader)
{
    if (scheme_register == NULL) {
        scheme_register =
            lh_SCHEME_LOADER_new(scheme_loader_hash, scheme_loader_cmp);
        if (scheme_register == NULL)
            return 0;
    }

    if (lh_SCHEME_LOADER_insert(scheme_register, scheme_loader) == NULL
        && lh_SCHEME_LOADER_error(scheme_register) > 0)
        return 0;

    return 1;
}

const SCHEME_LOADER *get_loader_int(const char *scheme)
{
    SCHEME_LOADER template = { 1, (char *)scheme, NULL };

    return lh_SCHEME_LOADER_retrieve(scheme_register, &template);
}

int unregister_loader_int(const char *scheme)
{
    SCHEME_LOADER template = { 1, (char *)scheme, NULL };
    SCHEME_LOADER *scheme_loader =
        lh_SCHEME_LOADER_delete(scheme_register, &template);

    if (scheme_loader == NULL) {
        STOREerr(STORE_F_UNREGISTER_LOADER_INT, STORE_R_UNREGISTERED_SCHEME);
        ERR_add_error_data(2, "scheme=", scheme);
        return 0;
    }

    scheme_loader_cleanup(scheme_loader);
    return 1;
}

void destroy_loaders_int(void)
{
    lh_SCHEME_LOADER_doall(scheme_register, scheme_loader_cleanup);
    lh_SCHEME_LOADER_free(scheme_register);
}
