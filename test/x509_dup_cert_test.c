/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include "testutil.h"

static int test_509_dup_cert(const char *cert_f)
{
    int ret = 0;
    X509_STORE_CTX *sctx = NULL;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    if (TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))
        && TEST_true(X509_load_cert_file(lookup, cert_f, X509_FILETYPE_PEM))
        && TEST_true(X509_load_cert_file(lookup, cert_f, X509_FILETYPE_PEM)))
        ret = 1;

    X509_STORE_CTX_free(sctx);
    X509_STORE_free(store);
    return ret;
}

int test_main(int argc, char **argv)
{
    if (!TEST_int_eq(argc, 2)) {
        TEST_info("usage: x509_dup_cert_test cert.pem");
        return 1;
    }

    return !test_509_dup_cert(argv[1]);
}
