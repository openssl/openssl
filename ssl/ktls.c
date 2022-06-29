/*
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssl_local.h"
#include "internal/ktls.h"

#ifndef OPENSSL_NO_KTLS_RX
 /*
  * Count the number of records that were not processed yet from record boundary.
  *
  * This function assumes that there are only fully formed records read in the
  * record layer. If read_ahead is enabled, then this might be false and this
  * function will fail.
  */
static int count_unprocessed_records(SSL *s)
{
    SSL3_BUFFER *rbuf = RECORD_LAYER_get_rbuf(&s->rlayer);
    PACKET pkt, subpkt;
    int count = 0;

    if (!PACKET_buf_init(&pkt, rbuf->buf + rbuf->offset, rbuf->left))
        return -1;

    while (PACKET_remaining(&pkt) > 0) {
        /* Skip record type and version */
        if (!PACKET_forward(&pkt, 3))
            return -1;

        /* Read until next record */
        if (!PACKET_get_length_prefixed_2(&pkt, &subpkt))
            return -1;

        count += 1;
    }

    return count;
}

/*
 * The kernel cannot offload receive if a partial TLS record has been read.
 * Check the read buffer for unprocessed records.  If the buffer contains a
 * partial record, fail and return 0.  Otherwise, update the sequence
 * number at *rec_seq for the count of unprocessed records and return 1.
 */
static int check_rx_read_ahead(SSL *s, unsigned char *rec_seq)
{
    int bit, count_unprocessed;

    count_unprocessed = count_unprocessed_records(s);
    if (count_unprocessed < 0)
        return 0;

    /* increment the crypto_info record sequence */
    while (count_unprocessed) {
        for (bit = 7; bit >= 0; bit--) { /* increment */
            ++rec_seq[bit];
            if (rec_seq[bit] != 0)
                break;
        }
        count_unprocessed--;

    }

    return 1;
}
#endif

#if defined(__FreeBSD__)
# include "crypto/cryptodev.h"

/*-
 * Check if a given cipher is supported by the KTLS interface.
 * The kernel might still fail the setsockopt() if no suitable
 * provider is found, but this checks if the socket option
 * supports the cipher suite used at all.
 */
int ktls_check_supported_cipher(const SSL *s, const EVP_CIPHER *c,
                                const EVP_CIPHER_CTX *dd)
{

    switch (s->version) {
    case TLS1_VERSION:
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
    case TLS1_3_VERSION:
        break;
    default:
        return 0;
    }

    switch (s->s3.tmp.new_cipher->algorithm_enc) {
    case SSL_AES128GCM:
    case SSL_AES256GCM:
        return 1;
# ifdef OPENSSL_KTLS_CHACHA20_POLY1305
    case SSL_CHACHA20POLY1305:
        return 1;
# endif
    case SSL_AES128:
    case SSL_AES256:
        if (s->ext.use_etm)
            return 0;
        switch (s->s3.tmp.new_cipher->algorithm_mac) {
        case SSL_SHA1:
        case SSL_SHA256:
        case SSL_SHA384:
            return 1;
        default:
            return 0;
        }
    default:
        return 0;
    }
}

/* Function to configure kernel TLS structure */
int ktls_configure_crypto(SSL *s, const EVP_CIPHER *c, EVP_CIPHER_CTX *dd,
                          void *rl_sequence, ktls_crypto_info_t *crypto_info,
                          int is_tx, unsigned char *iv,
                          unsigned char *key, unsigned char *mac_key,
                          size_t mac_secret_size)
{
    memset(crypto_info, 0, sizeof(*crypto_info));
    switch (s->s3.tmp.new_cipher->algorithm_enc) {
    case SSL_AES128GCM:
    case SSL_AES256GCM:
        crypto_info->cipher_algorithm = CRYPTO_AES_NIST_GCM_16;
        if (s->version == TLS1_3_VERSION)
            crypto_info->iv_len = EVP_CIPHER_CTX_get_iv_length(dd);
        else
            crypto_info->iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
        break;
# ifdef OPENSSL_KTLS_CHACHA20_POLY1305
    case SSL_CHACHA20POLY1305:
        crypto_info->cipher_algorithm = CRYPTO_CHACHA20_POLY1305;
        crypto_info->iv_len = EVP_CIPHER_CTX_get_iv_length(dd);
        break;
# endif
    case SSL_AES128:
    case SSL_AES256:
        switch (s->s3.tmp.new_cipher->algorithm_mac) {
        case SSL_SHA1:
            crypto_info->auth_algorithm = CRYPTO_SHA1_HMAC;
            break;
        case SSL_SHA256:
            crypto_info->auth_algorithm = CRYPTO_SHA2_256_HMAC;
            break;
        case SSL_SHA384:
            crypto_info->auth_algorithm = CRYPTO_SHA2_384_HMAC;
            break;
        default:
            return 0;
        }
        crypto_info->cipher_algorithm = CRYPTO_AES_CBC;
        crypto_info->iv_len = EVP_CIPHER_get_iv_length(c);
        crypto_info->auth_key = mac_key;
        crypto_info->auth_key_len = mac_secret_size;
        break;
    default:
        return 0;
    }
    crypto_info->cipher_key = key;
    crypto_info->cipher_key_len = EVP_CIPHER_get_key_length(c);
    crypto_info->iv = iv;
    crypto_info->tls_vmajor = (s->version >> 8) & 0x000000ff;
    crypto_info->tls_vminor = (s->version & 0x000000ff);
# ifdef TCP_RXTLS_ENABLE
    memcpy(crypto_info->rec_seq, rl_sequence, sizeof(crypto_info->rec_seq));
    if (!is_tx && !check_rx_read_ahead(s, crypto_info->rec_seq))
        return 0;
# else
    if (!is_tx)
        return 0;
# endif
    return 1;
};

#endif                         /* __FreeBSD__ */

#if defined(OPENSSL_SYS_LINUX)

/* Function to check supported ciphers in Linux */
int ktls_check_supported_cipher(const SSL *s, const EVP_CIPHER *c,
                                const EVP_CIPHER_CTX *dd)
{
    switch (s->version) {
    case TLS1_2_VERSION:
    case TLS1_3_VERSION:
        break;
    default:
        return 0;
    }

    /* check that cipher is AES_GCM_128, AES_GCM_256, AES_CCM_128 
     * or Chacha20-Poly1305
     */
# ifdef OPENSSL_KTLS_AES_CCM_128
    if (EVP_CIPHER_is_a(c, "AES-128-CCM")) {
        if (s->version == TLS_1_3_VERSION /* broken on 5.x kernels */
            || EVP_CIPHER_CTX_get_tag_length(dd) != EVP_CCM_TLS_TAG_LEN)
            return 0;
        return 1;
    } else
# endif
    if (0
# ifdef OPENSSL_KTLS_AES_GCM_128
        || EVP_CIPHER_is_a(c, "AES-128-GCM")
# endif
# ifdef OPENSSL_KTLS_AES_GCM_256
        || EVP_CIPHER_is_a(c, "AES-256-GCM")
# endif
# ifdef OPENSSL_KTLS_CHACHA20_POLY1305
        || EVP_CIPHER_is_a(c, "ChaCha20-Poly1305")
# endif
        ) {
        return 1;
    }
    return 0;
}

/* Function to configure kernel TLS structure */
int ktls_configure_crypto(SSL *s, const EVP_CIPHER *c, EVP_CIPHER_CTX *dd,
                          void *rl_sequence, ktls_crypto_info_t *crypto_info,
                          int is_tx, unsigned char *iv,
                          unsigned char *key, unsigned char *mac_key,
                          size_t mac_secret_size)
{
    unsigned char geniv[12];
    unsigned char *iiv = iv;

# ifdef OPENSSL_NO_KTLS_RX
    if (!is_tx)
        return 0;
# endif

    if (s->version == TLS1_2_VERSION &&
        EVP_CIPHER_get_mode(c) == EVP_CIPH_GCM_MODE) {
        if (!EVP_CIPHER_CTX_get_updated_iv(dd, geniv,
                                           EVP_GCM_TLS_FIXED_IV_LEN
                                           + EVP_GCM_TLS_EXPLICIT_IV_LEN))
            return 0;
        iiv = geniv;
    }

    memset(crypto_info, 0, sizeof(*crypto_info));
    switch (EVP_CIPHER_get_nid(c))
    {
# ifdef OPENSSL_KTLS_AES_GCM_128
    case NID_aes_128_gcm:
        crypto_info->gcm128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
        crypto_info->gcm128.info.version = s->version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->gcm128);
        memcpy(crypto_info->gcm128.iv, iiv + EVP_GCM_TLS_FIXED_IV_LEN,
               TLS_CIPHER_AES_GCM_128_IV_SIZE);
        memcpy(crypto_info->gcm128.salt, iiv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
        memcpy(crypto_info->gcm128.key, key, EVP_CIPHER_get_key_length(c));
        memcpy(crypto_info->gcm128.rec_seq, rl_sequence,
               TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
        if (!is_tx && !check_rx_read_ahead(s, crypto_info->gcm128.rec_seq))
            return 0;
        return 1;
# endif
# ifdef OPENSSL_KTLS_AES_GCM_256
    case NID_aes_256_gcm:
        crypto_info->gcm256.info.cipher_type = TLS_CIPHER_AES_GCM_256;
        crypto_info->gcm256.info.version = s->version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->gcm256);
        memcpy(crypto_info->gcm256.iv, iiv + EVP_GCM_TLS_FIXED_IV_LEN,
               TLS_CIPHER_AES_GCM_256_IV_SIZE);
        memcpy(crypto_info->gcm256.salt, iiv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
        memcpy(crypto_info->gcm256.key, key, EVP_CIPHER_get_key_length(c));
        memcpy(crypto_info->gcm256.rec_seq, rl_sequence,
               TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
        if (!is_tx && !check_rx_read_ahead(s, crypto_info->gcm256.rec_seq))
            return 0;
        return 1;
# endif
# ifdef OPENSSL_KTLS_AES_CCM_128
    case NID_aes_128_ccm:
        crypto_info->ccm128.info.cipher_type = TLS_CIPHER_AES_CCM_128;
        crypto_info->ccm128.info.version = s->version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->ccm128);
        memcpy(crypto_info->ccm128.iv, iiv + EVP_CCM_TLS_FIXED_IV_LEN,
               TLS_CIPHER_AES_CCM_128_IV_SIZE);
        memcpy(crypto_info->ccm128.salt, iiv, TLS_CIPHER_AES_CCM_128_SALT_SIZE);
        memcpy(crypto_info->ccm128.key, key, EVP_CIPHER_get_key_length(c));
        memcpy(crypto_info->ccm128.rec_seq, rl_sequence,
               TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE);
        if (!is_tx && !check_rx_read_ahead(s, crypto_info->ccm128.rec_seq))
            return 0;
        return 1;
# endif
# ifdef OPENSSL_KTLS_CHACHA20_POLY1305
    case NID_chacha20_poly1305:
        crypto_info->chacha20poly1305.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
        crypto_info->chacha20poly1305.info.version = s->version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->chacha20poly1305);
        memcpy(crypto_info->chacha20poly1305.iv, iiv,
               TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
        memcpy(crypto_info->chacha20poly1305.key, key,
               EVP_CIPHER_get_key_length(c));
        memcpy(crypto_info->chacha20poly1305.rec_seq, rl_sequence,
               TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
        if (!is_tx
                && !check_rx_read_ahead(s,
                                        crypto_info->chacha20poly1305.rec_seq))
            return 0;
        return 1;
# endif
    default:
        return 0;
    }

}

#endif /* OPENSSL_SYS_LINUX */
