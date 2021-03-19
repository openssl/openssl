/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_GLOBALS_H
# define OSSL_APPS_GLOBALS_H

#include <openssl/bio.h>

// probably move here (already in apps_config)
//extern char *default_config_file; /* may be "" */
extern BIO *bio_in;
extern BIO *bio_out;
extern BIO *bio_err;
// probably move those also here???
//extern const unsigned char tls13_aes128gcmsha256_id[];
//extern const unsigned char tls13_aes256gcmsha384_id[];
//extern BIO_ADDR *ourpeer;
//
//# define DB_type         0
//# define DB_exp_date     1
//# define DB_rev_date     2
//# define DB_serial       3      /* index - unique */
//# define DB_file         4
//# define DB_name         5      /* index - unique when active and not
//                                 * disabled */
//# define DB_NUMBER       6
//
//# define DB_TYPE_REV     'R'    /* Revoked  */
//# define DB_TYPE_EXP     'E'    /* Expired  */
//# define DB_TYPE_VAL     'V'    /* Valid ; inserted with: ca ... -valid */
//# define DB_TYPE_SUSP    'S'    /* Suspended  */

//extern char *psk_key;

//# define EXT_COPY_NONE   0
//# define EXT_COPY_ADD    1
//# define EXT_COPY_ALL    2
//
//# define NETSCAPE_CERT_HDR       "certificate"
//
//# define APP_PASS_LEN    1024

/*
 * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
 * so that the first bit will never be one, so that the DER encoding
 * rules won't force a leading octet.
 */
//# define SERIAL_RAND_BITS        159

//extern VERIFY_CB_ARGS verify_args;

#endif
