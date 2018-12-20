/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/params.h>

/* RSA Key data indicies */
#define RSA_N    0
#define RSA_E    1
#define RSA_D    2
#define RSA_P    3
#define RSA_Q    4
#define RSA_DMP1 5
#define RSA_DMQ1 6
#define RSA_IQMP 7

/* DSA Key data indicies */
#define DSA_P    0
#define DSA_Q    1
#define DSA_G    2
#define DSA_PUB  3
#define DSA_PRIV 4

/* EC Key data indicies */
#define EC_CURVE 0
#define EC_D     1
#define EC_X     2
#define EC_Y     3

/* Binary data */
typedef struct item_st {
    const unsigned char *data;
    int len;
} ST_ITEM;

typedef struct digest_st {
    int desc;
    const char *md_name;
    ST_ITEM plaintxt;
    ST_ITEM expected;
} ST_DIGEST;

typedef struct keydata_st {
    int id;
    ST_ITEM key;
} ST_KEYDATA;

typedef struct sig_st {
    int desc;
    const char *md_name;
    const EVP_PKEY_METHOD *pkey_meth;
    ST_KEYDATA *key_data;
    ST_ITEM msg;
    ST_ITEM sig;
} ST_SIGNATURE;

typedef struct cipher_st {
    int desc;
    const char *name;
    ST_ITEM plaintxt;
    ST_ITEM ciphertxt;
    ST_ITEM key;
    ST_ITEM iv;
    ST_ITEM add;
    ST_ITEM tag;
} ST_CIPHER;

/* Self test data for a DRBG */
typedef struct st_drbg_st {
    int desc;
    const char *name;
    int flags;
    ST_ITEM init_entropy;
    ST_ITEM pers_str;
    ST_ITEM gen_addin;
    ST_ITEM gen_ka;
    ST_ITEM reseed_entropy;
    ST_ITEM reseed_addin;
    ST_ITEM reseed_ka;
} ST_DRBG;

#if 0
typedef struct nvp_st {
    const char *name;
    const char *value;
} ST_NVP;

typedef struct SELF_TEST_KDF_st {
    const EVP_KDF_METHOD *meth;
    const SELF_TEST_NVP *ctrls;
    ST_ITEM expected;
} ST_KDF;
#endif

/* The test event phases */
#  define SELF_TEST_PHASE_NONE     0
#  define SELF_TEST_PHASE_START    1
#  define SELF_TEST_PHASE_CORRUPT  2
#  define SELF_TEST_PHASE_PASS     3
#  define SELF_TEST_PHASE_FAIL     4

/* Test event categories */
#  define SELF_TEST_TYPE_NONE               0
#  define SELF_TEST_TYPE_MODULE_INTEGRITY   1
#  define SELF_TEST_TYPE_INSTALL_INTEGRITY  2
#  define SELF_TEST_TYPE_PCT                3
#  define SELF_TEST_TYPE_KAT_CIPHER         4
#  define SELF_TEST_TYPE_KAT_DIGEST         5
#  define SELF_TEST_TYPE_KAT_SIGNATURE      6
#  define SELF_TEST_TYPE_DRBG               7
#  define SELF_TEST_TYPE_KA                 8
#  define SELF_TEST_TYPE_KAT_KDF            9

/* Test event sub categories */
#  define SELF_TEST_DESC_NONE           0
#  define SELF_TEST_DESC_INTEGRITY_HMAC 1
#  define SELF_TEST_DESC_PCT_RSA_PKCS1  2
#  define SELF_TEST_DESC_PCT_ECDSA      3
#  define SELF_TEST_DESC_PCT_DSA        4
#  define SELF_TEST_DESC_CIPHER_AES_GCM 5
#  define SELF_TEST_DESC_CIPHER_TDES    6
#  define SELF_TEST_DESC_MD_SHA1        7
#  define SELF_TEST_DESC_MD_SHA2        8
#  define SELF_TEST_DESC_MD_SHA3        9
#  define SELF_TEST_DESC_SIGN_DSA       10
#  define SELF_TEST_DESC_SIGN_RSA       11
#  define SELF_TEST_DESC_SIGN_ECDSA     12
#  define SELF_TEST_DESC_DRBG_CTR       13
#  define SELF_TEST_DESC_DRBG_HASH      14
#  define SELF_TEST_DESC_DRBG_HMAC      15
#  define SELF_TEST_DESC_KA_ECDH        16
#  define SELF_TEST_DESC_KA_ECDSA       17
#  define SELF_TEST_DESC_KDF_HKDF       18

typedef struct event_st
{
    int phase;
    int type;
    int desc;
    OSSL_PARAM params[4];
} ST_EVENT;

typedef int(*SELF_TEST_CB)(OSSL_PARAM *params);

typedef BIO *(*BIO_NEW_FILE_CB)(const char *filename, const char *mode);
typedef BIO *(*BIO_NEW_MEM_BUF_CB)(const void *buf, int len);
typedef int (*BIO_READ_CB)(BIO *bio, void *data, size_t data_len,
                           size_t *bytes_read);
typedef int (*BIO_FREE_CB)(BIO *bio);

typedef struct self_test_post_params_st {
    /* Used for FIPS module integrity check */
    char *module_filename; /* Module file to perform MAC on */
    unsigned char *module_checksum_data;  /* Expected module MAC integrity */
    size_t module_checksum_len;

    /* Used for KAT install indicator integrity check */
    char *indicator_data; /* Indicator data to perform MAC on */
    unsigned char *indicator_checksum_data; /* Expected MAC integrity value */
    size_t indicator_checksum_len;

    /* BIO callbacks supplied to the FIPS provider */
    BIO_NEW_FILE_CB bio_new_file_cb;
    BIO_NEW_MEM_BUF_CB bio_new_buffer_cb;
    BIO_FREE_CB bio_free_cb;
    /* Function used to read data from a BIO */
    BIO_READ_CB bio_read_cb;

    /* An optional application fips test callback */
    SELF_TEST_CB test_cb;
} SELF_TEST_POST_PARAMS;

int SELF_TEST_post(SELF_TEST_POST_PARAMS *params);
int SELF_TEST_keygen_pairwise_test_rsa(RSA *rsa);
int SELF_TEST_keygen_pairwise_test_ecdsa(EC_KEY *eckey);
int SELF_TEST_keygen_pairwise_test_dsa(DSA *dsa);

int self_test_kats(ST_EVENT *event);

void SELF_TEST_EVENT_init(ST_EVENT *ev);
void SELF_TEST_EVENT_onbegin(ST_EVENT *ev, int type, int desc);
void SELF_TEST_EVENT_onend(ST_EVENT *ev, int ret);
void SELF_TEST_EVENT_oncorrupt_byte(ST_EVENT *ev, unsigned char *bytes);
