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

/* Stuff from c_allkdf.c */
static const char * const id_pbkdf2_names[] =
    { LN_id_pbkdf2, NULL };


static const char * const id_scrypt_names[] =
    { SN_id_scrypt, LN_id_scrypt, NULL };


static const char * const tls1_prf_names[] =
    { SN_tls1_prf, LN_tls1_prf, NULL };


static const char * const hkdf_names[] =
    { SN_hkdf, LN_hkdf, NULL };


static const char * const sshkdf_names[] =
    { SN_sshkdf, LN_sshkdf, NULL };


static const char * const sskdf_names[] =
    { SN_sskdf, LN_sskdf, NULL };


static const char * const x963kdf_names[] =
    { SN_x963kdf, LN_x963kdf, NULL };


static const char * const * const all_kdf_names[] = {
    id_pbkdf2_names,
    id_scrypt_names,
    tls1_prf_names,
    hkdf_names,
    sshkdf_names,
    sskdf_names,
    x963kdf_names,
    NULL
};
