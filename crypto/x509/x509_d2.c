/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/x509.h>

int X509_STORE_set_default_paths(X509_STORE *ctx)
{
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
    if (lookup == NULL)
        return 0;
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        return 0;
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_store());
    if (lookup == NULL)
        return 0;
    X509_LOOKUP_add_store(lookup, NULL);

    /* clear any errors */
    ERR_clear_error();

    return 1;
}

int X509_STORE_load_file(X509_STORE *ctx, const char *file)
{
    X509_LOOKUP *lookup;

    if (file == NULL
        || (lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file())) == NULL
        || X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_PEM) == 0)
        return 0;

    return 1;
}

int X509_STORE_load_path(X509_STORE *ctx, const char *path)
{
    X509_LOOKUP *lookup;

    if (path == NULL
        || (lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir())) == NULL
        || X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM) == 0)
        return 0;

    return 1;
}

int X509_STORE_load_store(X509_STORE *ctx, const char *uri)
{
    X509_LOOKUP *lookup;

    if (uri == NULL
        || (lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_store())) == NULL
        || X509_LOOKUP_add_store(lookup, uri) == 0)
        return 0;

    return 1;
}

/* Deprecated */
#ifndef OPENSSL_NO_DEPRECATED_3_0
int X509_STORE_load_locations(X509_STORE *ctx, const char *file,
                              const char *path)
{
    if (file == NULL && path == NULL)
        return 0;
    if (file != NULL && !X509_STORE_load_file(ctx, file))
        return 0;
    if (path != NULL && !X509_STORE_load_path(ctx, path))
        return 0;
    return 1;
}
#endif
