/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "../../ssl_local.h"
#include "../record_local.h"
#include "recmethod_local.h"

static int tls_any_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                    unsigned char *key, size_t keylen,
                                    unsigned char *iv, size_t ivlen,
                                    unsigned char *mackey, size_t mackeylen,
                                    const EVP_CIPHER *ciph,
                                    size_t taglen,
                                    /* TODO(RECLAYER): This probably should not be an int */
                                    int mactype,
                                    const EVP_MD *md,
                                    const SSL_COMP *comp,
                                    /* TODO(RECLAYER): Remove me */
                                    SSL_CONNECTION *s)
{
    if (level != OSSL_RECORD_PROTECTION_LEVEL_NONE) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }

    /* No crypto protection at the "NONE" level so nothing to be done */

    return OSSL_RECORD_RETURN_SUCCESS;
}

static int tls_any_cipher(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs,
                          size_t n_recs, int sending, SSL_MAC_BUF *macs,
                          size_t macsize,
                          /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    return 1;
}

struct record_functions_st tls_any_funcs = {
    tls_any_set_crypto_state,
    tls_any_cipher,
    NULL
};
