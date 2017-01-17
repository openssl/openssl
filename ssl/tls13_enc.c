/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define TLS13_MAX_LABEL_LEN     246

/* Always filled with zeros */
static const unsigned char default_zeros[EVP_MAX_MD_SIZE];

/*
 * Given a |secret|; a |label| of length |labellen|; and a |hash| of the
 * handshake messages, derive a new secret |outlen| bytes long and store it in
 * the location pointed to be |out|. The |hash| value may be NULL. Returns 1 on
 * success  0 on failure.
 */
int tls13_hkdf_expand(SSL *s, const unsigned char *secret,
                             const unsigned char *label, size_t labellen,
                             const unsigned char *hash,
                             unsigned char *out, size_t outlen)
{
    const unsigned char label_prefix[] = "TLS 1.3, ";
    const EVP_MD *md = ssl_handshake_md(s);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int ret;
    size_t hkdflabellen;
    size_t hashlen;
    /*
     * 2 bytes for length of whole HkdfLabel + 1 byte for length of combined
     * prefix and label + bytes for the label itself + bytes for the hash
     */
    unsigned char hkdflabel[sizeof(uint16_t) + sizeof(uint8_t) +
                            + sizeof(label_prefix) + TLS13_MAX_LABEL_LEN
                            + EVP_MAX_MD_SIZE];
    WPACKET pkt;

    if (pctx == NULL)
        return 0;

    hashlen = EVP_MD_size(md);

    if (!WPACKET_init_static_len(&pkt, hkdflabel, sizeof(hkdflabel), 0)
            || !WPACKET_put_bytes_u16(&pkt, outlen)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_memcpy(&pkt, label_prefix, sizeof(label_prefix) - 1)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_close(&pkt)
            || !WPACKET_sub_memcpy_u8(&pkt, hash, (hash == NULL) ? 0 : hashlen)
            || !WPACKET_get_total_written(&pkt, &hkdflabellen)
            || !WPACKET_finish(&pkt)) {
        WPACKET_cleanup(&pkt);
        return 0;
    }

    ret = EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)
               <= 0
            || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, hashlen) <= 0
            || EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdflabel, hkdflabellen) <= 0
            || EVP_PKEY_derive(pctx, out, &outlen) <= 0;

    EVP_PKEY_CTX_free(pctx);

    return ret == 0;
}

/*
 * Given a |secret| generate a |key| of length |keylen| bytes. Returns 1 on
 * success  0 on failure.
 */
int tls13_derive_key(SSL *s, const unsigned char *secret, unsigned char *key,
                     size_t keylen)
{
    static const unsigned char keylabel[] = "key";

    return tls13_hkdf_expand(s, secret, keylabel, sizeof(keylabel) - 1, NULL,
                             key, keylen);
}

/*
 * Given a |secret| generate an |iv| of length |ivlen| bytes. Returns 1 on
 * success  0 on failure.
 */
int tls13_derive_iv(SSL *s, const unsigned char *secret, unsigned char *iv,
                    size_t ivlen)
{
    static const unsigned char ivlabel[] = "iv";

    return tls13_hkdf_expand(s, secret, ivlabel, sizeof(ivlabel) - 1, NULL,
                             iv, ivlen);
}

static int tls13_derive_finishedkey(SSL *s, const unsigned char *secret,
                                 unsigned char *fin, size_t finlen)
{
    static const unsigned char finishedlabel[] = "finished";

    return tls13_hkdf_expand(s, secret, finishedlabel,
                             sizeof(finishedlabel) - 1, NULL, fin, finlen);
}

/*
 * Given the previous secret |prevsecret| and a new input secret |insecret| of
 * length |insecretlen|, generate a new secret and store it in the location
 * pointed to by |outsecret|. Returns 1 on success  0 on failure.
 */
static int tls13_generate_secret(SSL *s, const unsigned char *prevsecret,
                                 const unsigned char *insecret,
                                 size_t insecretlen,
                                 unsigned char *outsecret)
{
    const EVP_MD *md = ssl_handshake_md(s);
    size_t mdlen, prevsecretlen;
    int ret;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (pctx == NULL)
        return 0;

    mdlen = EVP_MD_size(md);

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        prevsecretlen = mdlen;
    }

    ret = EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
               <= 0
            || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, insecretlen) <= 0
            || EVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen)
               <= 0
            || EVP_PKEY_derive(pctx, outsecret, &mdlen)
               <= 0;

    EVP_PKEY_CTX_free(pctx);
    return ret == 0;
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the early
 * secret. Returns 1 on success  0 on failure.
 */
int tls13_generate_early_secret(SSL *s, const unsigned char *insecret,
                                size_t insecretlen)
{
    return tls13_generate_secret(s, NULL, insecret, insecretlen,
                                 (unsigned char *)&s->early_secret);
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the
 * handshake secret. This requires the early secret to already have been
 * generated. Returns 1 on success  0 on failure.
 */
int tls13_generate_handshake_secret(SSL *s, const unsigned char *insecret,
                                size_t insecretlen)
{
    return tls13_generate_secret(s, s->early_secret, insecret, insecretlen,
                                 (unsigned char *)&s->handshake_secret);
}

/*
 * Given the handshake secret |prev| of length |prevlen| generate the master
 * secret and store its length in |*secret_size|. Returns 1 on success  0 on
 * failure.
 */
int tls13_generate_master_secret(SSL *s, unsigned char *out,
                                 unsigned char *prev, size_t prevlen,
                                 size_t *secret_size)
{
    *secret_size = EVP_MD_size(ssl_handshake_md(s));
    return tls13_generate_secret(s, prev, NULL, 0, out);
}

/*
 * Generates the mac for the Finished message. Returns the length of the MAC or
 * 0 on error.
 */
size_t tls13_final_finish_mac(SSL *s, const char *str, size_t slen,
                             unsigned char *out)
{
    const EVP_MD *md = ssl_handshake_md(s);
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hashlen, ret = 0;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ssl_handshake_hash(s, hash, sizeof(hash), &hashlen))
        goto err;

    if (str == s->method->ssl3_enc->server_finished_label)
        key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
                                   s->server_finished_secret, hashlen);
    else
        key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
                                   s->client_finished_secret, hashlen);

    if (key == NULL
            || ctx == NULL
            || EVP_DigestSignInit(ctx, NULL, md, NULL, key) <= 0
            || EVP_DigestSignUpdate(ctx, hash, hashlen) <= 0
            || EVP_DigestSignFinal(ctx, out, &hashlen) <= 0)
        goto err;

    ret = hashlen;
 err:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * There isn't really a key block in TLSv1.3, but we still need this function
 * for initialising the cipher and hash. Returns 1 on success or 0 on failure.
 */
int tls13_setup_key_block(SSL *s)
{
    const EVP_CIPHER *c;
    const EVP_MD *hash;
    int mac_type = NID_undef;

    s->session->cipher = s->s3->tmp.new_cipher;
    if (!ssl_cipher_get_evp
        (s->session, &c, &hash, &mac_type, NULL, NULL, 0)) {
        SSLerr(SSL_F_TLS13_SETUP_KEY_BLOCK, SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        return 0;
    }

    s->s3->tmp.new_sym_enc = c;
    s->s3->tmp.new_hash = hash;

    return 1;
}

int tls13_change_cipher_state(SSL *s, int which)
{
    static const unsigned char client_handshake_traffic[] =
        "client handshake traffic secret";
    static const unsigned char client_application_traffic[] =
        "client application traffic secret";
    static const unsigned char server_handshake_traffic[] =
        "server handshake traffic secret";
    static const unsigned char server_application_traffic[] =
        "server application traffic secret";
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char *iv;
    unsigned char secret[EVP_MAX_MD_SIZE];
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned char *hash = hashval;
    unsigned char *insecret;
    unsigned char *finsecret = NULL;
    EVP_CIPHER_CTX *ciph_ctx;
    const EVP_CIPHER *ciph = s->s3->tmp.new_sym_enc;
    size_t ivlen, keylen, finsecretlen = 0;
    const unsigned char *label;
    size_t labellen, hashlen = 0;
    int ret = 0;

    if (which & SSL3_CC_READ) {
        if (s->enc_read_ctx != NULL) {
            EVP_CIPHER_CTX_reset(s->enc_read_ctx);
        } else {
            s->enc_read_ctx = EVP_CIPHER_CTX_new();
            if (s->enc_read_ctx == NULL) {
                SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        ciph_ctx = s->enc_read_ctx;
        iv = s->read_iv;

        RECORD_LAYER_reset_read_sequence(&s->rlayer);
    } else {
        if (s->enc_write_ctx != NULL) {
            EVP_CIPHER_CTX_reset(s->enc_write_ctx);
        } else {
            s->enc_write_ctx = EVP_CIPHER_CTX_new();
            if (s->enc_write_ctx == NULL) {
                SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        ciph_ctx = s->enc_write_ctx;
        iv = s->write_iv;

        RECORD_LAYER_reset_write_sequence(&s->rlayer);
    }

    if (((which & SSL3_CC_CLIENT) && (which & SSL3_CC_WRITE))
            || ((which & SSL3_CC_SERVER) && (which & SSL3_CC_READ))) {
        if (which & SSL3_CC_HANDSHAKE) {
            insecret = s->handshake_secret;
            finsecret = s->client_finished_secret;
            finsecretlen = EVP_MD_size(ssl_handshake_md(s));
            label = client_handshake_traffic;
            labellen = sizeof(client_handshake_traffic) - 1;
        } else {
            int hashleni;

            insecret = s->session->master_key;
            label = client_application_traffic;
            labellen = sizeof(client_application_traffic) - 1;
            /*
             * For this we only use the handshake hashes up until the server
             * Finished hash. We do not include the client's Finished, which is
             * what ssl_handshake_hash() would give us. Instead we use the
             * previously saved value.
             */
            hash = s->server_finished_hash;
            hashleni = EVP_MD_CTX_size(s->s3->handshake_dgst);
            if (hashleni < 0) {
                SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            hashlen = (size_t)hashleni;
        }
    } else {
        if (which & SSL3_CC_HANDSHAKE) {
            insecret = s->handshake_secret;
            finsecret = s->server_finished_secret;
            finsecretlen = EVP_MD_size(ssl_handshake_md(s));
            label = server_handshake_traffic;
            labellen = sizeof(server_handshake_traffic) - 1;
        } else {
            insecret = s->session->master_key;
            label = server_application_traffic;
            labellen = sizeof(server_application_traffic) - 1;
        }
    }

    if (label != client_application_traffic) {
        if (!ssl3_digest_cached_records(s, 1)
                || !ssl_handshake_hash(s, hash, sizeof(hashval), &hashlen)) {
            SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        /*
         * Save the hash of handshakes up to now for use when we calculate the
         * client application traffic secret
         */
        if (label == server_application_traffic)
            memcpy(s->server_finished_hash, hash, hashlen);
    }

    if (!tls13_hkdf_expand(s, insecret, label, labellen, hash, secret,
                           hashlen)) {
        SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* TODO(size_t): convert me */
    keylen = EVP_CIPHER_key_length(ciph);
    ivlen = EVP_CIPHER_iv_length(ciph);

    if (!tls13_derive_key(s, secret, key, keylen)
            || !tls13_derive_iv(s, secret, iv, ivlen)
            || (finsecret != NULL && !tls13_derive_finishedkey(s, secret,
                                                               finsecret,
                                                               finsecretlen))) {
        SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (EVP_CipherInit_ex(ciph_ctx, ciph, NULL, key, NULL,
                          (which & SSL3_CC_WRITE)) <= 0) {
        SSLerr(SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_EVP_LIB);
        goto err;
    }

#ifdef OPENSSL_SSL_TRACE_CRYPTO
    if (s->msg_callback) {
        int wh = which & SSL3_CC_WRITE ? TLS1_RT_CRYPTO_WRITE : 0;

        if (ciph->key_len)
            s->msg_callback(2, s->version, wh | TLS1_RT_CRYPTO_KEY,
                            key, ciph->key_len, s, s->msg_callback_arg);

        wh |= TLS1_RT_CRYPTO_IV;
        s->msg_callback(2, s->version, wh, iv, ivlen, s,
                        s->msg_callback_arg);
    }
#endif

    ret = 1;
 err:
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(key, sizeof(key));
    return ret;
}

int tls13_alert_code(int code)
{
    if (code == SSL_AD_MISSING_EXTENSION)
        return code;

    return tls1_alert_code(code);
}
