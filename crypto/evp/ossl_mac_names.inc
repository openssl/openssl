/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ONLY included by evp_fetch.c */

#include <openssl/obj_mac.h>

/* Stuff from c_allm.c */
static const char * const blake2bmac_names[] =
    { SN_blake2bmac, LN_blake2bmac, NULL };
static const char * const blake2smac_names[] =
    { SN_blake2smac, LN_blake2smac, NULL };

static const char * const cmac_names[] =
    { SN_cmac, LN_cmac, NULL };

static const char * const gmac_names[] =
    { SN_gmac, LN_gmac, NULL };

static const char * const hmac_names[] =
    { SN_hmac, LN_hmac, NULL };

static const char * const kmac128_names[] =
    { SN_kmac128, LN_kmac128, NULL };
static const char * const kmac256_names[] =
    { SN_kmac256, LN_kmac256, NULL };

static const char * const siphash_names[] =
    { SN_siphash, LN_siphash, NULL };

static const char * const poly1305_names[] =
    { SN_poly1305, LN_poly1305, NULL };

static const char * const pbkdf2_names[] =
    { /* SN_id_pbkdf2, */ LN_id_pbkdf2, NULL };


static const char * const * const all_mac_names[] = {
    blake2bmac_names,
    blake2smac_names,
    cmac_names,
    gmac_names,
    hmac_names,
    kmac128_names,
    kmac256_names,
    siphash_names,
    poly1305_names,
    pbkdf2_names,
    NULL
};
