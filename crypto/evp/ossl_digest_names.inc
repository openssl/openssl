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

/* Stuff from c_alld.c */
static const char * const md5_names[] =
    { SN_md5, LN_md5, "ssl-md5", NULL };
static const char * const md5_sha1_names[] =
    { SN_md5_sha1, LN_md5_sha1, NULL };


static const char * const sha1_names[] =
    { SN_sha1, LN_sha1, "ssl3-sha1", NULL };


static const char * const sha1WithRSAEncryption_names[] =
    { SN_sha1WithRSAEncryption, SN_sha1WithRSA, NULL };


static const char * const mdc2_names[] =
    { SN_mdc2, LN_mdc2, NULL };


static const char * const ripemd160_names[] =
    { SN_ripemd160, LN_ripemd160, "ripemd", "rmd160", NULL };


static const char * const sha224_names[] =
    { SN_sha224, LN_sha224, NULL };
static const char * const sha256_names[] =
    { SN_sha256, LN_sha256, NULL };
static const char * const sha384_names[] =
    { SN_sha384, LN_sha384, NULL };
static const char * const sha512_names[] =
    { SN_sha512, LN_sha512, NULL };
static const char * const sha512_224_names[] =
    { SN_sha512_224, LN_sha512_224, NULL };
static const char * const sha512_256_names[] =
    { SN_sha512_256, LN_sha512_256, NULL };


static const char * const whirlpool_names[] =
    { SN_whirlpool, NULL };


static const char * const sm3_names[] =
    { SN_sm3, LN_sm3, NULL };


static const char * const blake2b512_names[] =
    { SN_blake2b512, LN_blake2b512, NULL };
static const char * const blake2s256_names[] =
    { SN_blake2s256, LN_blake2s256, NULL };


static const char * const sha3_224_names[] =
    { SN_sha3_224, LN_sha3_224, NULL };
static const char * const sha3_256_names[] =
    { SN_sha3_256, LN_sha3_256, NULL };
static const char * const sha3_384_names[] =
    { SN_sha3_384, LN_sha3_384, NULL };
static const char * const sha3_512_names[] =
    { SN_sha3_512, LN_sha3_512, NULL };


static const char * const shake128_names[] =
    { SN_shake128, LN_shake128, NULL };
static const char * const shake256_names[] =
    { SN_shake256, LN_shake256, NULL };


static const char * const * const all_digest_names[] = {
    md5_names,
    md5_sha1_names,
    sha1_names,
    sha1WithRSAEncryption_names,
    mdc2_names,
    ripemd160_names,
    sha224_names,
    sha256_names,
    sha384_names,
    sha512_names,
    sha512_224_names,
    sha512_256_names,
    whirlpool_names,
    sm3_names,
    blake2b512_names,
    blake2s256_names,
    sha3_224_names,
    sha3_256_names,
    sha3_384_names,
    sha3_512_names,
    shake128_names,
    shake256_names,
    NULL
};
