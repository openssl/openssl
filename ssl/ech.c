/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "ssl_local.h"
#include "ech_local.h"
#include "statem/statem_local.h"
#include <openssl/rand.h>
#include <openssl/trace.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* a size for some crypto vars */
# define OSSL_ECH_CRYPTO_VAR_SIZE 2048

/*
 * @brief encode binary buffer as ascii hex
 * @param out is an allocated buffer for the ascii hex string
 * @param outsize is the size of the buffer
 * @param in is the input binary buffer
 * @param inlen is the size of the binary buffer
 * @return 1 for good otherwise bad
 */
static int ah_encode(char *out, size_t outsize,
                     const unsigned char *in, size_t inlen)
{
    size_t i;

    if (outsize < 2 * inlen + 1)
        return 0;
    for (i = 0; i != inlen; i++) {
        uint8_t tn = (in[i] >> 4) & 0x0f;
        uint8_t bn = (in[i] & 0x0f);

        out[2 * i] = (tn < 10 ? tn + '0' : (tn - 10 + 'A'));
        out[2 * i + 1] = (bn < 10 ? bn + '0' : (bn - 10 + 'A'));
    }
    out[2 * i] = '\0';
    return 1;
}

/*
 * @brief has a buffer as a pretend file name being ascii-hex of hashed buffer
 * @param buf is the input buffer
 * @param blen is the length of buf
 * @param ah_hash is a pointer to where to the result 
 * @param ah_len is the length of ah_hash
 */
static int ech_hash_pub_as_fname(const unsigned char *buf, size_t blen,
                                 char *ah_hash, size_t ah_len)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned int hashlen;

    if (((md = EVP_MD_fetch(NULL, "SHA2-256", NULL)) == NULL)
        || ((mdctx = EVP_MD_CTX_new()) == NULL)
        || EVP_DigestInit_ex(mdctx, md, NULL) <= 0
        || EVP_DigestUpdate(mdctx, buf, blen) <= 0
        || EVP_DigestFinal_ex(mdctx, hashval, &hashlen) <= 0) {
        if (md != NULL)
            EVP_MD_free(md);
        if (mdctx != NULL)
            EVP_MD_CTX_free(mdctx);
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_MD_free(md);
    EVP_MD_CTX_free(mdctx);
    if (ah_encode(ah_hash, ah_len, hashval, hashlen) != 1)
        return 0;
    return 1;
}

/* 
 * API calls build around OSSL_ECHSSTORE 
 */

OSSL_ECHSTORE *OSSL_ECHSTORE_init(OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_ECHSTORE *es = NULL;

    es = OPENSSL_zalloc(sizeof(OSSL_ECHSTORE));
    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    es->libctx = libctx;
    es->propq = propq;
    return es;
}

static void OSSL_ECHEXT_free(OSSL_ECHEXT *e)
{
    OPENSSL_free(e->val);
    OPENSSL_free(e);
    return;
}

static void OSSL_ECHSTORE_entry_free(OSSL_ECHSTORE_entry *ee)
{
    OPENSSL_free(ee->public_name);
    OPENSSL_free(ee->pub);
    OPENSSL_free(ee->pemfname);
    EVP_PKEY_free(ee->keyshare);
    OPENSSL_free(ee->encoded);
    OPENSSL_free(ee->suites);
    sk_OSSL_ECHEXT_pop_free(ee->exts, OSSL_ECHEXT_free);
    OPENSSL_free(ee);
    return;
}

void OSSL_ECHSTORE_free(OSSL_ECHSTORE *es)
{
    sk_OSSL_ECHSTORE_entry_pop_free(es->entries, OSSL_ECHSTORE_entry_free);
    OPENSSL_free(es);
    return;
}

int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *es,
                             uint16_t echversion, uint16_t max_name_length,
                             const char *public_name, OSSL_HPKE_SUITE suite)
{
    size_t pnlen = 0;
    size_t publen = OSSL_ECH_CRYPTO_VAR_SIZE;
    unsigned char pub[OSSL_ECH_CRYPTO_VAR_SIZE];
    int rv = 0;
    unsigned char *bp = NULL;
    size_t bblen = 0;
    EVP_PKEY *privp = NULL;
    uint8_t config_id = 0;
    WPACKET epkt;
    BUF_MEM *epkt_mem = NULL;
    OSSL_ECHSTORE_entry *ee = NULL;
    char pembuf[2 * EVP_MAX_MD_SIZE + 1];
    size_t pembuflen = 2 * EVP_MAX_MD_SIZE + 1;

    /* basic checks */
    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    pnlen = (public_name == NULL ? 0 : strlen(public_name));
    if (pnlen > OSSL_ECH_MAX_PUBLICNAME
        || max_name_length > OSSL_ECH_MAX_MAXNAMELEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* this used have more versions and will again in future */
    switch (echversion) {
    case OSSL_ECH_RFCXXXX_VERSION:
        break;
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* so WPAKCET_cleanup() won't go wrong */
    memset(&epkt, 0, sizeof(epkt));
    /* random config_id */
    if (RAND_bytes((unsigned char *)&config_id, 1) <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* key pair */
    if (OSSL_HPKE_keygen(suite, pub, &publen, &privp, NULL, 0,
                         es->libctx, es->propq) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     *   Reminder, for draft-13 we want this:
     *
     *   opaque HpkePublicKey<1..2^16-1>;
     *   uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
     *   struct {
     *       HpkeKdfId kdf_id;
     *       HpkeAeadId aead_id;
     *   } HpkeSymmetricCipherSuite;
     *   struct {
     *       uint8 config_id;
     *       HpkeKemId kem_id;
     *       HpkePublicKey public_key;
     *       HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
     *   } HpkeKeyConfig;
     *   struct {
     *       HpkeKeyConfig key_config;
     *       uint8 maximum_name_length;
     *       opaque public_name<1..255>;
     *       Extension extensions<0..2^16-1>;
     *   } ECHConfigContents;
     *   struct {
     *       uint16 version;
     *       uint16 length;
     *       select (ECHConfig.version) {
     *         case 0xfe0d: ECHConfigContents contents;
     *       }
     *   } ECHConfig;
     *   ECHConfig ECHConfigList<1..2^16-1>;
     */
    if ((epkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(epkt_mem, OSSL_ECH_MAX_ECHCONFIG_LEN)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* config id, KEM, public, KDF, AEAD, max name len, public_name, exts */
    if (!WPACKET_init(&epkt, epkt_mem)
        || (bp = WPACKET_get_curr(&epkt)) == NULL
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u16(&epkt, echversion)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u8(&epkt, config_id)
        || !WPACKET_put_bytes_u16(&epkt, suite.kem_id)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_memcpy(&epkt, pub, publen)
        || !WPACKET_close(&epkt)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u16(&epkt, suite.kdf_id)
        || !WPACKET_put_bytes_u16(&epkt, suite.aead_id)
        || !WPACKET_close(&epkt)
        || !WPACKET_put_bytes_u8(&epkt, max_name_length)
        || !WPACKET_start_sub_packet_u8(&epkt)
        || !WPACKET_memcpy(&epkt, public_name, pnlen)
        || !WPACKET_close(&epkt)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_memcpy(&epkt, NULL, 0) /* no extensions */
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* bp, bblen has encoding */
    WPACKET_get_total_written(&epkt, &bblen);
    if ((ee = OPENSSL_zalloc(sizeof(OSSL_ECHSTORE_entry))) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->suites = OPENSSL_malloc(sizeof(OSSL_HPKE_SUITE));
    if (ee->suites == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ech_hash_pub_as_fname(pub, publen, pembuf, pembuflen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->version = echversion;
    ee->pub_len = publen;
    ee->pub = OPENSSL_memdup(pub, publen);
    if (ee->pub == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->nsuites = 1;
    ee->suites[0] = suite;
    ee->public_name = OPENSSL_strdup(public_name);
    if (ee->public_name == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->max_name_length = max_name_length;
    ee->config_id = config_id;
    ee->keyshare = privp;
    ee->encoded = OPENSSL_memdup(bp, bblen);
    if (ee->encoded == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->encoded_len = bblen;
    ee->pemfname = OPENSSL_strdup(pembuf);
    if (ee->pemfname == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->loadtime = time(0);
    /* push entry into store */
    if (es->entries == NULL)
        es->entries = sk_OSSL_ECHSTORE_entry_new_null();
    if (es->entries == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!sk_OSSL_ECHSTORE_entry_push(es->entries, ee)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    WPACKET_cleanup(&epkt);
    BUF_MEM_free(epkt_mem);
    return 1;

err:
    EVP_PKEY_free(privp);
    WPACKET_cleanup(&epkt);
    BUF_MEM_free(epkt_mem);
    OSSL_ECHSTORE_entry_free(ee);
    OPENSSL_free(ee);
    return rv;
}

int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *es, int index, BIO *out)
{
    OSSL_ECHSTORE_entry *ee = NULL;
    char *b64val = NULL;
    size_t b64len = 0;
    int rv = 0, num = 0, chosen = 0;

    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    num = sk_OSSL_ECHSTORE_entry_num(es->entries);
    if (num <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (index >= num) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (index == OSSL_ECHSTORE_LAST)
        chosen = num - 1;
    else
        chosen = index;
    ee = sk_OSSL_ECHSTORE_entry_value(es->entries, chosen);
    if (ee == NULL || ee->keyshare == NULL || ee->encoded == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    b64val = OPENSSL_zalloc(2 * ee->encoded_len);
    if (b64val == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* private key first */
    if (!PEM_write_bio_PrivateKey(out, ee->keyshare, NULL, NULL, 0,
                                  NULL, NULL)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    b64len = EVP_EncodeBlock((unsigned char*)b64val,
                             ee->encoded, ee->encoded_len);
    if (BIO_printf(out, "-----BEGIN ECHCONFIG-----\n") <= 0
        || BIO_write(out, b64val, b64len) != b64len
        || BIO_printf(out, "\n") <= 0
        || BIO_printf(out, "-----END ECHCONFIG-----\n") <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = 1;
err:
    OPENSSL_free(b64val);
    return rv;
}

int OSSL_ECHSTORE_read_echconfiglist(OSSL_ECHSTORE *es, BIO *in)
{
    return 0;
}

int OSSL_ECHSTORE_get1_info(OSSL_ECHSTORE *es, OSSL_ECH_INFO **info,
                            int *count)
{
    return 0;
}

int OSSL_ECHSTORE_downselect(OSSL_ECHSTORE *es, int index)
{
    return 0;
}

int OSSL_ECHSTORE_set1_key_and_read_pem(OSSL_ECHSTORE *es, EVP_PKEY *priv,
                                        BIO *in, int for_retry)
{
    return 0;
}

int OSSL_ECHSTORE_read_pem(OSSL_ECHSTORE *es, BIO *in, int for_retry)
{
    return 0;
}

int OSSL_ECHSTORE_num_keys(OSSL_ECHSTORE *es, int *numkeys)
{
    return 0;
}

int OSSL_ECHSTORE_flush_keys(OSSL_ECHSTORE *es, time_t age)
{
    return 0;
}

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *info, int count)
{
    return;
}

int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *info, int count)
{
    return 0;
}

int SSL_CTX_set1_echstore(SSL_CTX *ctx, OSSL_ECHSTORE *es)
{
    return 0;
}

int SSL_set1_echstore(SSL *s, OSSL_ECHSTORE *es)
{
    return 0;
}

OSSL_ECHSTORE *SSL_CTX_get1_echstore(const SSL_CTX *ctx)
{
    return NULL;
}

OSSL_ECHSTORE *SSL_get1_echstore(const SSL *s)
{
    return NULL;
}

int SSL_ech_set_server_names(SSL *s, const char *inner_name,
                             const char *outer_name, int no_outer)
{
    return 0;
}

int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name, int no_outer)
{
    return 0;
}

int SSL_ech_set_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                  const size_t protos_len)
{
    return 0;
}

int SSL_ech_get1_status(SSL *s, char **inner_sni, char **outer_sni)
{
    return 0;
}

int SSL_ech_set_grease_suite(SSL *s, const char *suite)
{
    return 0;
}

int SSL_ech_set_grease_type(SSL *s, uint16_t type)
{
    return 0;
}

void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f)
{
    return;
}

int SSL_ech_get_retry_config(SSL *s, unsigned char **ec, size_t *eclen)
{
    return 0;
}

int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *s, const unsigned char *protos,
                                      const size_t protos_len)
{
    return 0;
}

int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            unsigned char **hrrtok, size_t *toklen)
{
    return 0;
}

void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f)
{
    return;
}


