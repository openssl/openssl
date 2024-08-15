/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal data structures and prototypes for handling
 * Encrypted ClientHello (ECH)
 */
#ifndef OPENSSL_NO_ECH

# ifndef HEADER_ECH_LOCAL_H
#  define HEADER_ECH_LOCAL_H

#  include <openssl/ssl.h>
#  include <openssl/ech.h>
#  include <openssl/hpke.h>

/*
 * Define this to get loads more lines of tracing which is
 * very useful for interop.
 * This needs tracing enabled at build time, e.g.:
 *          $ ./config enable-ssl-trace enable-trace
 * This added tracing will finally (mostly) disappear once the ECH RFC
 * has issued, but is very useful for interop testing so some of it might
 * be retained.
 */
#  define OSSL_ECH_SUPERVERBOSE

/*
 * Reminder of what goes in DNS for ECH RFC XXXX
 *
 *     opaque HpkePublicKey<1..2^16-1>;
 *     uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
 *     uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
 *     uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
 *     struct {
 *         HpkeKdfId kdf_id;
 *         HpkeAeadId aead_id;
 *     } HpkeSymmetricCipherSuite;
 *     struct {
 *         uint8 config_id;
 *         HpkeKemId kem_id;
 *         HpkePublicKey public_key;
 *         HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
 *     } HpkeKeyConfig;
 *     struct {
 *         HpkeKeyConfig key_config;
 *         uint8 maximum_name_length;
 *         opaque public_name<1..255>;
 *         Extension extensions<0..2^16-1>;
 *     } ECHConfigContents;
 *     struct {
 *         uint16 version;
 *         uint16 length;
 *         select (ECHConfig.version) {
 *           case 0xfe0d: ECHConfigContents contents;
 *         }
 *     } ECHConfig;
 *     ECHConfig ECHConfigList<1..2^16-1>;
 */

typedef struct ossl_echext_st {
    uint16_t type;
    uint16_t len;
    unsigned char *val;
} OSSL_ECHEXT;

DEFINE_STACK_OF(OSSL_ECHEXT)

typedef struct ossl_echstore_entry_st {
    uint16_t version; /* 0xff0d for draft-13 */
    char *public_name;
    size_t pub_len;
    unsigned char *pub;
    unsigned int nsuites;
    OSSL_HPKE_SUITE *suites;
    uint8_t max_name_length;
    uint8_t config_id;
    STACK_OF(OSSL_ECHEXT) *exts;
    char *pemfname; /* name of PEM file from which this was loaded */
    time_t loadtime; /* time public and private key were loaded from file */
    EVP_PKEY *keyshare; /* long(ish) term ECH private keyshare on a server */
    int for_retry; /* whether to use this ECHConfigList in a retry */
    size_t encoded_len; /* length of overall encoded content */
    unsigned char *encoded; /* overall encoded content */
} OSSL_ECHSTORE_ENTRY;

DEFINE_STACK_OF(OSSL_ECHSTORE_ENTRY)

struct ossl_echstore_st {
    STACK_OF(OSSL_ECHSTORE_ENTRY) *entries;
    OSSL_LIB_CTX *libctx;
    const char *propq;
};

# endif
#endif
