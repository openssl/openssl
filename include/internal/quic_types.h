/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_TYPES_H
# define OSSL_QUIC_TYPES_H

# include <openssl/ssl.h>

/* QUIC packet number representation. */
typedef uint64_t QUIC_PN;
# define QUIC_PN_INVALID            UINT64_MAX

static ossl_unused ossl_inline QUIC_PN ossl_quic_pn_max(QUIC_PN a, QUIC_PN b)
{
    return a > b ? a : b;
}

static ossl_unused ossl_inline QUIC_PN ossl_quic_pn_min(QUIC_PN a, QUIC_PN b)
{
    return a < b ? a : b;
}

#endif
