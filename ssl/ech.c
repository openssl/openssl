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

#ifndef OPENSSL_NO_ECH

/* a size for some crypto vars */
# define OSSL_ECH_CRYPTO_VAR_SIZE 2048

/*
 * @brief hash a buffer as a pretend file name being ascii-hex of hashed buffer
 * @param es is the OSSL_ECHSTORE we're dealing with
 * @param buf is the input buffer
 * @param blen is the length of buf
 * @param ah_hash is a pointer to where to put the result
 * @param ah_len is the length of ah_hash
 */
static int ech_hash_pub_as_fname(OSSL_ECHSTORE *es,
                                 const unsigned char *buf, size_t blen,
                                 char *ah_hash, size_t ah_len)
{
    unsigned char hashval[EVP_MAX_MD_SIZE];
    size_t hashlen, actual_ah_len;

    if (es == NULL
        || EVP_Q_digest(es->libctx, "SHA2-256", es->propq,
                        buf, blen, hashval, &hashlen) != 1
        || OPENSSL_buf2hexstr_ex(ah_hash, ah_len, &actual_ah_len,
                                 hashval, hashlen, '\0') != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return 1;
}

/*
 * API calls built around OSSL_ECHSTORE
 */

OSSL_ECHSTORE *OSSL_ECHSTORE_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_ECHSTORE *es = NULL;

    es = OPENSSL_zalloc(sizeof(*es));
    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    es->libctx = libctx;
    es->propq = propq;
    return es;
}

static void ossl_echext_free(OSSL_ECHEXT *e)
{
    if (e == NULL)
        return;
    OPENSSL_free(e->val);
    OPENSSL_free(e);
    return;
}

static void ossl_echstore_entry_free(OSSL_ECHSTORE_ENTRY *ee)
{
    if (ee == NULL)
        return;
    OPENSSL_free(ee->public_name);
    OPENSSL_free(ee->pub);
    OPENSSL_free(ee->pemfname);
    EVP_PKEY_free(ee->keyshare);
    OPENSSL_free(ee->encoded);
    OPENSSL_free(ee->suites);
    sk_OSSL_ECHEXT_pop_free(ee->exts, ossl_echext_free);
    OPENSSL_free(ee);
    return;
}

void OSSL_ECHSTORE_free(OSSL_ECHSTORE *es)
{
    if (es == NULL)
        return;
    sk_OSSL_ECHSTORE_ENTRY_pop_free(es->entries, ossl_echstore_entry_free);
    OPENSSL_free(es);
    return;
}

int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *es,
                             uint16_t echversion, uint8_t max_name_length,
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
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    char pembuf[2 * EVP_MAX_MD_SIZE + 1];
    size_t pembuflen = 2 * EVP_MAX_MD_SIZE + 1;

    /* basic checks */
    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    pnlen = (public_name == NULL ? 0 : strlen(public_name));
    if (pnlen == 0 || pnlen > OSSL_ECH_MAX_PUBLICNAME
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

    /* so WPACKET_cleanup() won't go wrong */
    memset(&epkt, 0, sizeof(epkt));
    /* random config_id */
    if (RAND_bytes_ex(es->libctx, (unsigned char *)&config_id, 1,
                      RAND_DRBG_STRENGTH) <= 0) {
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
    if ((ee = OPENSSL_zalloc(sizeof(*ee))) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->suites = OPENSSL_malloc(sizeof(OSSL_HPKE_SUITE));
    if (ee->suites == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ech_hash_pub_as_fname(es, pub, publen, pembuf, pembuflen) != 1) {
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
        es->entries = sk_OSSL_ECHSTORE_ENTRY_new_null();
    if (es->entries == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!sk_OSSL_ECHSTORE_ENTRY_push(es->entries, ee)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    WPACKET_finish(&epkt);
    BUF_MEM_free(epkt_mem);
    return 1;

err:
    EVP_PKEY_free(privp);
    WPACKET_cleanup(&epkt);
    BUF_MEM_free(epkt_mem);
    ossl_echstore_entry_free(ee);
    OPENSSL_free(ee);
    return rv;
}

int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *es, int index, BIO *out)
{
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int rv = 0, num = 0, chosen = 0;

    if (es == NULL) {
        /*
         * TODO(ECH): this is a bit of a bogus error, just so as
         * to get the `make update` command to add the required
         * error number. We don't need it yet, but it's involved
         * in some of the build artefacts, so may as well jump
         * the gun a bit on it.
         */
        ERR_raise(ERR_LIB_SSL, SSL_R_ECH_REQUIRED);
        return 0;
    }
    num = sk_OSSL_ECHSTORE_ENTRY_num(es->entries);
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
    ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, chosen);
    if (ee == NULL || ee->keyshare == NULL || ee->encoded == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* private key first */
    if (!PEM_write_bio_PrivateKey(out, ee->keyshare, NULL, NULL, 0,
                                  NULL, NULL)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (PEM_write_bio(out, PEM_STRING_ECHCONFIG, NULL,
                      ee->encoded, ee->encoded_len) <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = 1;
err:
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

#endif
