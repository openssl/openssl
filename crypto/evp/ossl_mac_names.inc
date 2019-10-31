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
static const char blake2bmac_names[] =
    SN_blake2bmac ":" LN_blake2bmac;
static const char blake2smac_names[] =
    SN_blake2smac ":" LN_blake2smac;

static const char cmac_names[] =
    SN_cmac ":" LN_cmac;

static const char gmac_names[] =
    SN_gmac ":" LN_gmac;

static const char hmac_names[] =
    SN_hmac ":" LN_hmac;

static const char kmac128_names[] =
    SN_kmac128 ":" LN_kmac128;
static const char kmac256_names[] =
    SN_kmac256 ":" LN_kmac256;

static const char siphash_names[] =
    SN_siphash ":" LN_siphash;

static const char poly1305_names[] =
    SN_poly1305 ":" LN_poly1305;

static const char pbkdf2_names[] =
    /* SN_id_pbkdf2 ":" */ LN_id_pbkdf2;


static const char * const all_mac_names[] = {
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
